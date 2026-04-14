#[cfg(test)]
mod tests {
    use serde_yml::{
        value::{tagged::nobang, Tag, TaggedValue},
        Value,
    };

    /// Test for creating a new Tag.
    #[test]
    fn test_tag_new() {
        let tag = Tag::new("foo");
        assert_eq!(tag.string, "foo");
    }

    /// Test for converting bytes into a Tag.
    #[test]
    fn test_try_from_tag() {
        let tag = Tag::try_from(&b"foo"[..]).unwrap();
        assert_eq!(tag.string, "foo");
    }

    /// Test for copying a TaggedValue.
    #[test]
    fn test_tagged_value_copy() {
        let tag = Tag::new("foo");
        let value = Value::String("bar".to_owned());
        let tagged_value = TaggedValue { tag, value };
        let copied = tagged_value.copy();
        assert_eq!(tagged_value, copied);
    }

    /// Test for removing '!' from a string.
    #[test]
    fn test_nobang_with_bang() {
        let nobanged = nobang("!foo");
        assert_eq!(nobanged, "foo");
    }

    /// Test for removing '!' from a string without '!'.
    #[test]
    fn test_nobang_without_bang() {
        let nobanged = nobang("foo");
        assert_eq!(nobanged, "foo");
    }
}
