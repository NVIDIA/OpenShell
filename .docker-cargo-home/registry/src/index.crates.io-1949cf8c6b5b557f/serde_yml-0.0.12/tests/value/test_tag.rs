#[cfg(test)]
mod tests {
    use serde_yml::libyml::tag::{Tag, TagFormatError};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    /// Test the `Tag::new` function to ensure it correctly creates a `Tag` from a string.
    #[test]
    fn test_tag_new() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        assert_eq!(&*tag, b"tag:yaml.org,2002:test");
    }

    /// Test the `Tag::starts_with` function to check if a tag starts with a given prefix.
    #[test]
    fn test_tag_starts_with() {
        let tag = Tag::new("tag:yaml.org,2002:test");

        // Test positive case
        assert_eq!(tag.starts_with("tag:yaml.org"), Ok(true));

        // Test negative case
        assert_eq!(tag.starts_with("tag:other.org"), Ok(false));

        // Test error case
        assert_eq!(
            tag.starts_with("tag:yaml.org,2002:test:extra"),
            Err(TagFormatError)
        );
    }

    /// Test the `PartialEq` implementation for `Tag` with a string.
    #[test]
    fn test_tag_partial_eq() {
        let tag = Tag::new("tag:yaml.org,2002:test");

        // Test equality
        assert_eq!(tag, "tag:yaml.org,2002:test");

        // Test inequality
        assert_ne!(tag, "tag:yaml.org,2002:other");
    }

    /// Test the `Deref` implementation for `Tag`.
    #[test]
    fn test_tag_deref() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        let tag_bytes: &[u8] = &tag;
        assert_eq!(tag_bytes, b"tag:yaml.org,2002:test");
    }

    /// Test the `Debug` implementation for `Tag`.
    #[test]
    fn test_tag_debug() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        let debug_str = format!("{:?}", tag);
        assert_eq!(debug_str, "\"tag:yaml.org,2002:test\"");
    }

    /// Test the predefined constant values for `Tag`.
    #[test]
    fn test_tag_constants() {
        assert_eq!(Tag::NULL, "tag:yaml.org,2002:null");
        assert_eq!(Tag::BOOL, "tag:yaml.org,2002:bool");
        assert_eq!(Tag::INT, "tag:yaml.org,2002:int");
        assert_eq!(Tag::FLOAT, "tag:yaml.org,2002:float");
    }

    /// Test the `Display` implementation for `TagFormatError`.
    #[test]
    fn test_tag_format_error_display() {
        let error = TagFormatError;
        let error_message = format!("{}", error);
        assert_eq!(
            error_message,
            "Error occurred while formatting tag"
        );
    }

    /// Test the `PartialEq` implementation for `Tag` with `str`.
    #[test]
    fn test_tag_partial_eq_str() {
        let tag = Tag::new("tag:yaml.org,2002:test");

        // Test equality with str
        assert!(tag == "tag:yaml.org,2002:test");

        // Test inequality with str
        assert!(tag != "tag:yaml.org,2002:other");
    }

    /// Test the `PartialEq` implementation for `Tag` with `&str`.
    #[test]
    fn test_tag_partial_eq_str_ref() {
        let tag = Tag::new("tag:yaml.org,2002:test");

        // Test equality with &str
        assert!(tag == "tag:yaml.org,2002:test");

        // Test inequality with &str
        assert!(tag != "tag:yaml.org,2002:other");
    }

    /// Test the `Clone` implementation for `Tag`.
    #[test]
    fn test_tag_clone() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        let cloned_tag = tag.clone();
        assert_eq!(tag, cloned_tag);
    }

    /// Test the `Hash` implementation for `Tag`.
    #[test]
    fn test_tag_hash() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        let mut hasher = DefaultHasher::new();
        tag.hash(&mut hasher);
        let hash1 = hasher.finish();

        let mut hasher = DefaultHasher::new();
        tag.hash(&mut hasher);
        let hash2 = hasher.finish();

        assert_eq!(hash1, hash2);
    }

    /// Tests the `Debug` implementation for `TagFormatError`.
    #[test]
    fn test_tag_format_error_debug() {
        let error = TagFormatError;
        let debug_str = format!("{:?}", error);
        assert_eq!(debug_str, "TagFormatError");
    }

    /// Tests the `Error` trait implementation for `TagFormatError`.
    #[test]
    fn test_tag_format_error_error() {
        let error = TagFormatError;
        let error_message = error.to_string();
        assert_eq!(
            error_message,
            "Error occurred while formatting tag"
        );
    }

    /// Tests the error case when the prefix is longer than the tag in the `starts_with` method.
    #[test]
    fn test_tag_starts_with_error() {
        let tag = Tag::new("short");
        let prefix = "longer_prefix";
        assert_eq!(tag.starts_with(prefix), Err(TagFormatError));
    }

    /// Tests the `PartialEq` implementation for `Tag` with `&str` slices.
    #[test]
    fn test_tag_partial_eq_str_slice() {
        let tag = Tag::new("tag:yaml.org,2002:test");

        // Test equality with &str slice
        assert!(tag == "tag:yaml.org,2002:test"[..]);

        // Test inequality with &str slice
        assert!(tag != "tag:yaml.org,2002:other"[..]);
    }

    /// Test the behaviour of Tag::new with an empty string
    #[test]
    fn test_tag_new_empty_string() {
        let tag = Tag::new("");
        assert_eq!(&*tag, b"");
    }

    /// Test the behaviour of Tag::starts_with with an empty prefix
    #[test]
    fn test_tag_starts_with_empty_prefix() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        assert_eq!(tag.starts_with(""), Ok(true));
    }

    /// Test the behaviour of Tag::starts_with with an equal prefix
    #[test]
    fn test_tag_starts_with_equal_prefix() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        assert_eq!(tag.starts_with("tag:yaml.org,2002:test"), Ok(true));
    }

    /// Test the behaviour of Tag::starts_with with a prefix that has a different case
    #[test]
    fn test_tag_starts_with_case_sensitive() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        assert_eq!(tag.starts_with("TAG:YAML.ORG"), Ok(false));
    }

    /// Test the behaviour of PartialEq with an empty string
    #[test]
    fn test_tag_partial_eq_empty_string() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        assert!(tag != "");
    }

    /// Test the behaviour of PartialEq with a non-ASCII string
    #[test]
    fn test_tag_partial_eq_non_ascii() {
        let tag = Tag::new("tag:yaml.org,2002:test");
        assert!(tag != "tag:yaml.org,2002:tést");
    }
}
