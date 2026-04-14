#[cfg(test)]
mod tests {
    use serde_yml::libyml::tag::{Tag, TagFormatError};

    /// Tests the creation of a new Tag instance using the NULL constant.
    /// Verifies that the created Tag instance is not null.
    #[test]
    fn test_new_tag_null() {
        let tag_null = Tag::new(Tag::NULL);
        assert!(!tag_null.is_empty());
    }

    /// Tests the creation of a new Tag instance with a custom tag.
    /// Verifies that the created Tag instance matches the provided custom tag.
    #[test]
    fn test_new_custom_tag() {
        let custom_tag = Tag::new("tag:example.org,2024:custom");
        assert_eq!(custom_tag, "tag:example.org,2024:custom");
    }

    /// Tests if a Tag starts with a given prefix.
    /// Verifies that the method returns true for a matching prefix and false otherwise.
    #[test]
    fn test_tag_starts_with() {
        let custom_tag = Tag::new("tag:example.org,2024:custom");
        assert!(custom_tag.starts_with("tag:example.org").unwrap());
        assert!(!custom_tag.starts_with("tag:example.com").unwrap());
    }

    /// Tests the handling of TagFormatError when the prefix is longer than the tag.
    /// Verifies that the method returns an error for a longer prefix.
    #[test]
    fn test_tag_starts_with_error() {
        let custom_tag = Tag::new("tag:example.org,2024:custom");
        let result =
            custom_tag.starts_with("tag:example.org,2024:custom:extra");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TagFormatError);
    }

    /// Tests the comparison of a Tag with a &str.
    /// Verifies that the comparison returns true for matching values and false otherwise.
    #[test]
    fn test_tag_comparison() {
        let custom_tag = Tag::new("tag:example.org,2024:custom");
        let comparison_str = "tag:example.org,2024:custom";
        assert_eq!(custom_tag, comparison_str);

        let non_matching_str = "tag:example.org,2024:other";
        assert_ne!(custom_tag, non_matching_str);
    }

    /// Tests the Deref implementation to access the underlying byte slice.
    /// Verifies that the dereferenced value matches the original tag string.
    #[test]
    fn test_tag_deref() {
        let custom_tag = Tag::new("tag:example.org,2024:custom");
        let tag_bytes: &[u8] = &custom_tag;
        assert_eq!(tag_bytes, b"tag:example.org,2024:custom");
    }

    /// Tests the Debug implementation for a Tag instance.
    /// Verifies that the debug representation of the Tag instance is correct.
    #[test]
    fn test_tag_debug() {
        let custom_tag = Tag::new("tag:example.org,2024:custom");
        let debug_str = format!("{:?}", custom_tag);
        assert_eq!(debug_str, "\"tag:example.org,2024:custom\"");
    }

    /// Tests the creation of Tag instances using Tag constants for BOOL, INT, and FLOAT.
    /// Verifies that the created Tag instances match the respective constants.
    #[test]
    fn test_tag_constants() {
        let tag_bool = Tag::new(Tag::BOOL);
        assert_eq!(tag_bool, Tag::BOOL);

        let tag_int = Tag::new(Tag::INT);
        assert_eq!(tag_int, Tag::INT);

        let tag_float = Tag::new(Tag::FLOAT);
        assert_eq!(tag_float, Tag::FLOAT);
    }
}
