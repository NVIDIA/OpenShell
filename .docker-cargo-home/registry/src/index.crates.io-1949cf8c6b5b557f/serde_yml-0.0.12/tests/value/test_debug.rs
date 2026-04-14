#[cfg(test)]
mod tests {
    use serde_yml::mapping::Mapping;
    use serde_yml::value::{Number, Value};

    #[test]
    fn test_debug_value_null() {
        let value = Value::Null;
        assert_eq!(format!("{:?}", value), "Null");
    }

    #[test]
    fn test_debug_value_bool() {
        let value = Value::Bool(true);
        assert_eq!(format!("{:?}", value), "Bool(true)");
    }

    #[test]
    fn test_debug_value_number() {
        let value = Value::Number(Number::from(42));
        assert_eq!(format!("{:?}", value), "Number(42)");
    }

    #[test]
    fn test_debug_value_string() {
        let value = Value::String("Hello, world!".to_string());
        assert_eq!(format!("{:?}", value), "String(\"Hello, world!\")");
    }

    #[test]
    fn test_debug_value_sequence() {
        let value =
            Value::Sequence(vec![Value::Null, Value::Bool(true)]);
        assert_eq!(
            format!("{:?}", value),
            "Sequence [Null, Bool(true)]"
        );
    }

    #[test]
    fn test_debug_value_mapping() {
        let mut mapping = Mapping::new();
        mapping.insert(
            Value::String("name".to_string()),
            Value::String("John".to_string()),
        );
        mapping.insert(
            Value::String("age".to_string()),
            Value::Number(30.into()),
        );

        let value = Value::Mapping(mapping);
        assert_eq!(
            format!("{:?}", value),
            "Mapping {\"name\": String(\"John\"), \"age\": Number(30)}"
        );
    }

    #[test]
    fn test_debug_number() {
        let number = Number::from(42);
        assert_eq!(format!("{:?}", number), "Number(42)");
    }
}
