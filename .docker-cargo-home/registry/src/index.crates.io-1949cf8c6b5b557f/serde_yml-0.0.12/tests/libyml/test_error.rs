#[cfg(test)]
mod tests {
    // use libyml as sys;
    use serde_yml::libyml::error::Result;

    #[test]
    fn test_result_ok() {
        let value: Result<i32> = Ok(42);
        match value {
            Ok(v) => assert_eq!(v, 42),
            Err(_) => panic!("Expected Ok(42), but got an Err"),
        }
    }

    #[test]
    fn test_result_ok_with_string() {
        let value: Result<String> = Ok(String::from("Hello, world!"));
        match value {
            Ok(v) => assert_eq!(v, "Hello, world!"),
            Err(_) => {
                panic!("Expected Ok(\"Hello, world!\"), but got an Err")
            }
        }
    }
}
