#[cfg(test)]
mod tests {
    use serde_yml::value::{Mapping, Value};
    use std::borrow::Cow;

    // Conversion tests for non-numeric types

    #[test]
    fn test_from_bool() {
        // Verify conversion from bool to Value
        // Given a bool value,
        let b = false;
        // When converting it to Value,
        let x: Value = b.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Bool(false));
    }

    #[test]
    fn test_from_string() {
        // Verify conversion from String to Value
        // Given a String,
        let s: String = "lorem".to_string();
        // When converting it to Value,
        let x: Value = s.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::String("lorem".to_string()));
    }

    #[test]
    fn test_from_str() {
        // Verify conversion from &str to Value
        // Given a string slice,
        let s: &str = "lorem";
        // When converting it to Value,
        let x: Value = s.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::String("lorem".to_string()));
    }

    #[test]
    fn test_from_cow_borrowed() {
        // Verify conversion from Cow<str> (borrowed) to Value
        // Given a borrowed Cow<str>,
        let s: Cow<'_, str> = Cow::Borrowed("lorem");
        // When converting it to Value,
        let x: Value = s.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::String("lorem".to_string()));
    }

    #[test]
    fn test_from_cow_owned() {
        // Verify conversion from Cow<str> (owned) to Value
        // Given an owned Cow<str>,
        let s: Cow<'_, str> = Cow::Owned("lorem".to_string());
        // When converting it to Value,
        let x: Value = s.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::String("lorem".to_string()));
    }

    #[test]
    fn test_from_mapping() {
        // Verify conversion from Mapping to Value
        // Given a Mapping,
        let mut m = Mapping::new();
        m.insert("Lorem".into(), "ipsum".into());
        // When converting it to Value,
        let x: Value = m.into();
        // Then it should be converted correctly.
        assert_eq!(
            x,
            Value::Mapping(Mapping::from_iter(vec![(
                "Lorem".into(),
                "ipsum".into()
            )]))
        );
    }

    #[test]
    fn test_from_vec() {
        // Verify conversion from Vec to Value
        // Given a Vec,
        let v = vec!["lorem", "ipsum", "dolor"];
        // When converting it to Value,
        let x: Value = v.into();
        // Then it should be converted correctly.
        assert_eq!(
            x,
            Value::Sequence(vec![
                "lorem".into(),
                "ipsum".into(),
                "dolor".into()
            ])
        );
    }

    #[test]
    fn test_from_slice() {
        // Verify conversion from slice to Value
        // Given a slice,
        let v: &[&str] = &["lorem", "ipsum", "dolor"];
        // When converting it to Value,
        let x: Value = v.into();
        // Then it should be converted correctly.
        assert_eq!(
            x,
            Value::Sequence(vec![
                "lorem".into(),
                "ipsum".into(),
                "dolor".into()
            ])
        );
    }

    #[test]
    fn test_from_iterator() {
        // Verify conversion from iterator to Value
        // Given an iterator that repeats a value,
        let v = std::iter::repeat(42).take(5);
        // When collecting it into Value,
        let x: Value = v.collect();
        // Then it should be converted correctly.
        assert_eq!(
            x,
            Value::Sequence(vec![
                42.into(),
                42.into(),
                42.into(),
                42.into(),
                42.into()
            ])
        );

        // Given a Vec,
        let v: Vec<_> = vec!["lorem", "ipsum", "dolor"];
        // When converting it to Value,
        let x: Value = v.into_iter().collect();
        // Then it should be converted correctly.
        assert_eq!(
            x,
            Value::Sequence(vec![
                "lorem".into(),
                "ipsum".into(),
                "dolor".into()
            ])
        );

        // Given values to collect,
        let x: Value =
            Value::from_iter(vec!["lorem", "ipsum", "dolor"]);
        // Then they should be converted correctly.
        assert_eq!(
            x,
            Value::Sequence(vec![
                "lorem".into(),
                "ipsum".into(),
                "dolor".into()
            ])
        );
    }

    // Conversion tests for numeric types

    #[test]
    fn test_from_number_i8() {
        // Verify conversion from i8 to Value
        // Given an i8 value,
        let n: i8 = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_i16() {
        // Verify conversion from i16 to Value
        // Given an i16 value,
        let n: i16 = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_i32() {
        // Verify conversion from i32 to Value
        // Given an i32 value,
        let n: i32 = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_i64() {
        // Verify conversion from i64 to Value
        // Given an i64 value,
        let n: i64 = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_isize() {
        // Verify conversion from isize to Value
        // Given an isize value,
        let n: isize = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_u8() {
        // Verify conversion from u8 to Value
        // Given a u8 value,
        let n: u8 = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_u16() {
        // Verify conversion from u16 to Value
        // Given a u16 value,
        let n: u16 = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_u32() {
        // Verify conversion from u32 to Value
        // Given a u32 value,
        let n: u32 = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_u64() {
        // Verify conversion from u64 to Value
        // Given a u64 value,
        let n: u64 = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_usize() {
        // Verify conversion from usize to Value
        // Given a usize value,
        let n: usize = 42;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.into()));
    }

    #[test]
    fn test_from_number_f32() {
        // Verify conversion from f32 to Value
        // Given an f32 value,
        let n: f32 = 42.5;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.5.into()));
    }

    #[test]
    fn test_from_number_f64() {
        // Verify conversion from f64 to Value
        // Given an f64 value,
        let n: f64 = 42.5;
        // When converting it to Value,
        let x: Value = n.into();
        // Then it should be converted correctly.
        assert_eq!(x, Value::Number(42.5.into()));
    }
}
