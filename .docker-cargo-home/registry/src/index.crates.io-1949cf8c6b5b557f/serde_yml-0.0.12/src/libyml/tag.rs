use crate::libyml::safe_cstr;
use memchr::memchr;
use std::{
    fmt::{self, Debug, Display},
    ops::Deref,
};

/// Custom error type for Tag operations.
#[derive(Clone, Copy, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct TagFormatError;

impl Display for TagFormatError {
    /// Formats the error message for display.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter to write the error message to.
    ///
    /// # Returns
    ///
    /// Returns `fmt::Result` indicating the success or failure of the operation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error occurred while formatting tag")
    }
}

impl std::error::Error for TagFormatError {}

/// Represents a tag in a YAML document.
/// A tag specifies the data type or semantic meaning of a value.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash)]
pub struct Tag(pub(in crate::libyml) Box<[u8]>);

impl Tag {
    /// The null tag, representing a null value.
    pub const NULL: &'static str = "tag:yaml.org,2002:null";

    /// The bool tag, representing a boolean value.
    pub const BOOL: &'static str = "tag:yaml.org,2002:bool";

    /// The int tag, representing an integer value.
    pub const INT: &'static str = "tag:yaml.org,2002:int";

    /// The float tag, representing a floating-point value.
    pub const FLOAT: &'static str = "tag:yaml.org,2002:float";

    /// Checks if the tag starts with the given prefix.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The prefix to check against.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the tag starts with the given prefix, `Ok(false)` otherwise.
    /// Returns an error if the prefix is longer than the tag.
    ///
    /// # Errors
    ///
    /// Returns `TagFormatError` if the prefix length is greater than the tag length.
    pub fn starts_with(
        &self,
        prefix: &str,
    ) -> Result<bool, TagFormatError> {
        if prefix.len() > self.0.len() {
            Err(TagFormatError)
        } else {
            let prefix_bytes = prefix.as_bytes();
            let tag_bytes = &self.0[..prefix_bytes.len()];
            Ok(tag_bytes == prefix_bytes)
        }
    }

    /// Creates a new `Tag` instance from a `&str` input.
    ///
    /// # Arguments
    ///
    /// * `tag_str` - The string representing the tag.
    ///
    /// # Returns
    ///
    /// Returns a `Tag` instance representing the specified tag string.
    pub fn new(tag_str: &str) -> Tag {
        Tag(Box::from(tag_str.as_bytes()))
    }
}

impl PartialEq<str> for Tag {
    /// Checks if the tag is equal to the given string.
    ///
    /// # Arguments
    ///
    /// * `other` - The string to compare against.
    ///
    /// # Returns
    ///
    /// Returns `true` if the tag is equal to the given string, `false` otherwise.
    fn eq(&self, other: &str) -> bool {
        self.0 == other.as_bytes().into()
    }
}

impl PartialEq<&str> for Tag {
    /// Checks if the tag is equal to the given string slice.
    ///
    /// # Arguments
    ///
    /// * `other` - The string slice to compare against.
    ///
    /// # Returns
    ///
    /// Returns `true` if the tag is equal to the given string slice, `false` otherwise.
    fn eq(&self, other: &&str) -> bool {
        self.0 == other.as_bytes().into()
    }
}

impl Deref for Tag {
    type Target = [u8];

    /// Dereferences the tag to its underlying byte slice.
    ///
    /// # Returns
    ///
    /// Returns a reference to the underlying byte slice of the tag.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Tag {
    /// Formats the tag for debugging purposes.
    ///
    /// # Arguments
    ///
    /// * `formatter` - The formatter to write the debug output to.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the formatting was successful, or an error otherwise.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(null_pos) = memchr(b'\0', &self.0) {
            safe_cstr::debug_lossy(&self.0[..null_pos], formatter)
        } else {
            safe_cstr::debug_lossy(&self.0, formatter)
        }
    }
}
