#[cfg(test)]
mod tests {
    use serde_yml::Value;

    // Tests for equality comparison with owned string
    #[test]
    fn test_eq_string() {
        assert_eq!(Value::String("lorem".into()), *"lorem");
    }

    // Tests for equality comparison with string literal
    #[test]
    fn test_eq_str() {
        assert_eq!(Value::String("lorem".into()), "lorem");
    }

    // Tests for equality comparison with owned string
    #[test]
    fn test_eq_string_owned() {
        assert_eq!(Value::String("lorem".into()), "lorem".to_string());
    }

    // Tests for equality comparison with boolean
    #[test]
    fn test_eq_bool() {
        assert_eq!(Value::Bool(true), true);
    }

    // Tests for equality comparison with i8
    #[test]
    fn test_eq_i8() {
        assert_eq!(Value::Number(10.into()), 10i8);
    }

    // Tests for equality comparison with i16
    #[test]
    fn test_eq_i16() {
        assert_eq!(Value::Number(10.into()), 10i16);
    }

    // Tests for equality comparison with i32
    #[test]
    fn test_eq_i32() {
        assert_eq!(Value::Number(10.into()), 10i32);
    }

    // Tests for equality comparison with i64
    #[test]
    fn test_eq_i64() {
        assert_eq!(Value::Number(10.into()), 10i64);
    }

    // Tests for equality comparison with isize
    #[test]
    fn test_eq_isize() {
        assert_eq!(Value::Number(10.into()), 10isize);
    }

    // Tests for equality comparison with u8
    #[test]
    fn test_eq_u8() {
        assert_eq!(Value::Number(10.into()), 10u8);
    }

    // Tests for equality comparison with u16
    #[test]
    fn test_eq_u16() {
        assert_eq!(Value::Number(10.into()), 10u16);
    }

    // Tests for equality comparison with u32
    #[test]
    fn test_eq_u32() {
        assert_eq!(Value::Number(10.into()), 10u32);
    }

    // Tests for equality comparison with u64
    #[test]
    fn test_eq_u64() {
        assert_eq!(Value::Number(10.into()), 10u64);
    }

    // Tests for equality comparison with usize
    #[test]
    fn test_eq_usize() {
        assert_eq!(Value::Number(10.into()), 10usize);
    }

    // Tests for equality comparison with f32
    #[test]
    fn test_eq_f32() {
        assert_eq!(Value::Number(10.0.into()), 10.0f32);
    }

    // Tests for equality comparison with f64
    #[test]
    fn test_eq_f64() {
        assert_eq!(Value::Number(10.0.into()), 10.0f64);
    }

    // Tests for inequality comparison with owned string
    #[test]
    fn test_ne_string() {
        assert_ne!(Value::String("lorem".into()), *"ipsum");
    }

    // Tests for inequality comparison with boolean
    #[test]
    fn test_ne_bool() {
        assert_ne!(Value::Bool(true), false);
    }

    // Tests for inequality comparison with number
    #[test]
    fn test_ne_number() {
        assert_ne!(Value::Number(10.into()), 20i32);
    }

    // Tests for inequality comparison with incompatible types
    #[test]
    fn test_ne_incompatible_types() {
        assert_ne!(Value::String("lorem".into()), true);
        assert_ne!(Value::Bool(true), 10i32);
        assert_ne!(Value::Number(10.into()), "10");
    }

    // Tests for equality comparison with reference
    #[test]
    fn test_eq_ref() {
        let v = Value::String("lorem".into());
        assert_eq!(&v, "lorem");
    }

    // Tests for equality comparison with mutable reference
    #[test]
    fn test_eq_mut_ref() {
        let mut v = Value::Number(10.into());
        assert_eq!(&mut v, 10i32);
    }

    // Tests for equality comparison with minimum and maximum values
    #[test]
    fn test_eq_min_max() {
        assert_eq!(Value::Number(i64::MIN.into()), i64::MIN);
        assert_eq!(Value::Number(i64::MAX.into()), i64::MAX);
        assert_eq!(Value::Number(u64::MAX.into()), u64::MAX);
        assert_eq!(Value::Number(f64::MIN.into()), f64::MIN);
        assert_eq!(Value::Number(f64::MAX.into()), f64::MAX);
    }
}
