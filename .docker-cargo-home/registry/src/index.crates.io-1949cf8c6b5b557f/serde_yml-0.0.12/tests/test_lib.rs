#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_yml::{
        from_reader, from_slice, from_str, to_string, Mapping, Number,
        Result, Sequence, Value,
    };
    use std::io::Cursor;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Point {
        x: f64,
        y: f64,
    }

    /// Test serialization of a Point struct to YAML string
    #[test]
    fn test_serialization() -> Result<()> {
        let point = Point { x: 1.0, y: 2.0 };
        let yaml = to_string(&point)?;
        assert_eq!(yaml, "x: 1.0\n'y': 2.0\n");
        Ok(())
    }

    /// Test deserialization of a YAML string to a Point struct
    #[test]
    fn test_deserialization() -> Result<()> {
        let yaml = "x: 1.0\ny: 2.0\n";
        let point: Point = from_str(yaml)?;
        assert_eq!(point, Point { x: 1.0, y: 2.0 });
        Ok(())
    }

    /// Test deserialization from a reader (Cursor in this case)
    #[test]
    fn test_from_reader() -> Result<()> {
        let yaml = "x: 1.0\ny: 2.0\n";
        let mut cursor = Cursor::new(yaml);
        let point: Point = from_reader(&mut cursor)?;
        assert_eq!(point, Point { x: 1.0, y: 2.0 });
        Ok(())
    }

    /// Test deserialization from a byte slice
    #[test]
    fn test_from_slice() -> Result<()> {
        let yaml = b"x: 1.0\ny: 2.0\n";
        let point: Point = from_slice(yaml)?;
        assert_eq!(point, Point { x: 1.0, y: 2.0 });
        Ok(())
    }

    /// Test Mapping functionality
    #[test]
    fn test_mapping() {
        let mut map = Mapping::new();
        map.insert(
            Value::String("key".to_string()),
            Value::Number(Number::from(42)),
        );
        assert_eq!(map.get("key").and_then(Value::as_i64), Some(42));
    }

    /// Test Sequence functionality
    #[test]
    fn test_sequence() {
        let seq = Sequence::from(vec![
            Value::Number(Number::from(1)),
            Value::Number(Number::from(2)),
        ]);
        assert_eq!(seq.len(), 2);
        assert_eq!(seq[0].as_i64(), Some(1));
    }
}
