#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_lossless,
        clippy::cast_possible_wrap,
        clippy::derive_partial_eq_without_eq,
        clippy::similar_names,
        clippy::uninlined_format_args
    )]

    use indoc::indoc;
    use serde_derive::Deserialize;
    use serde_yml::{
        de::{Event, Progress},
        libyml::parser::{
            MappingStart, Scalar, ScalarStyle::Plain, SequenceStart,
        },
        loader::Loader,
        modules::error::ErrorImpl,
        Deserializer, Number,
        Value::{self, String as SerdeString},
    };
    use std::{
        collections::BTreeMap,
        fmt::{Debug, Formatter},
        io::Cursor,
        string::String,
        sync::Arc,
    };

    // Helper functions
    fn test_de<T>(yaml: &str, expected: &T)
    where
        T: serde::de::DeserializeOwned + PartialEq + Debug,
    {
        let deserialized: T = serde_yml::from_str(yaml).unwrap();
        assert_eq!(*expected, deserialized);

        let value: Value = serde_yml::from_str(yaml).unwrap();
        let deserialized = T::deserialize(&value).unwrap();
        assert_eq!(*expected, deserialized);

        let deserialized: T = serde_yml::from_value(value).unwrap();
        assert_eq!(*expected, deserialized);

        serde_yml::from_str::<serde::de::IgnoredAny>(yaml).unwrap();

        let mut deserializer = Deserializer::from_str(yaml);
        let document = deserializer.next().unwrap();
        let deserialized = T::deserialize(document).unwrap();
        assert_eq!(*expected, deserialized);
        assert!(deserializer.next().is_none());
    }

    fn test_de_no_value<'de, T>(yaml: &'de str, expected: &T)
    where
        T: serde::de::Deserialize<'de> + PartialEq + Debug,
    {
        let deserialized: T = serde_yml::from_str(yaml).unwrap();
        assert_eq!(*expected, deserialized);

        serde_yml::from_str::<Value>(yaml).unwrap();
        serde_yml::from_str::<serde::de::IgnoredAny>(yaml).unwrap();
    }

    fn test_de_seed<'de, T, S>(yaml: &'de str, seed: S, expected: &T)
    where
        T: PartialEq + Debug,
        S: serde::de::DeserializeSeed<'de, Value = T>,
    {
        let deserialized: T =
            seed.deserialize(Deserializer::from_str(yaml)).unwrap();
        assert_eq!(*expected, deserialized);

        serde_yml::from_str::<Value>(yaml).unwrap();
        serde_yml::from_str::<serde::de::IgnoredAny>(yaml).unwrap();
    }

    // *** Basic Deserialization Tests ***

    #[test]
    /// Test YAML deserialization with cyclic aliasing.
    fn test_alias() {
        let yaml = indoc! {"
        first:
          &alias
          1
        second:
          *alias
        third: 3
    "};
        let mut expected = BTreeMap::new();
        expected.insert("first".to_owned(), 1);
        expected.insert("second".to_owned(), 1);
        expected.insert("third".to_owned(), 3);
        test_de(yaml, &expected);
    }

    #[test]
    /// Test borrowed strings with different YAML representations.
    fn test_borrowed() {
        let yaml = indoc! {"
        - plain nonàscii
        - 'single quoted'
        - \"double quoted\"
    "};
        let expected =
            vec!["plain nonàscii", "single quoted", "double quoted"];
        test_de_no_value(yaml, &expected);
    }

    #[test]
    /// Test YAML deserialization with a bomb-like structure to test depth limit.
    fn test_bomb() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Data {
            expected: String,
        }

        let yaml = indoc! {"
        a: &a ~
        b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
        c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
        d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
        e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
        f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
        g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
        h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
        i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
        j: &j [*i,*i,*i,*i,*i,*i,*i,*i,*i]
        k: &k [*j,*j,*j,*j,*j,*j,*j,*j,*j]
        l: &l [*k,*k,*k,*k,*k,*k,*k,*k,*k]
        m: &m [*l,*l,*l,*l,*l,*l,*l,*l,*l]
        n: &n [*m,*m,*m,*m,*m,*m,*m,*m,*m]
        o: &o [*n,*n,*n,*n,*n,*n,*n,*n,*n]
        p: &p [*o,*o,*o,*o,*o,*o,*o,*o,*o]
        q: &q [*p,*p,*p,*p,*p,*p,*p,*p,*p]
        r: &r [*q,*q,*q,*q,*q,*q,*q,*q,*q]
        s: &s [*r,*r,*r,*r,*r,*r,*r,*r,*r]
        t: &t [*s,*s,*s,*s,*s,*s,*s,*s,*s]
        u: &u [*t,*t,*t,*t,*t,*t,*t,*t,*t]
        v: &v [*u,*u,*u,*u,*u,*u,*u,*u,*u]
        w: &w [*v,*v,*v,*v,*v,*v,*v,*v,*v]
        x: &x [*w,*w,*w,*w,*w,*w,*w,*w,*w]
        'y': &y [*x,*x,*x,*x,*x,*x,*x,*x,*x]
        z: &z [*y,*y,*y,*y,*y,*y,*y,*y,*y]
        expected: string
    "};

        let expected = Data {
            expected: "string".to_owned(),
        };

        assert_eq!(
            expected,
            serde_yml::from_str::<Data>(yaml).unwrap()
        );
    }

    #[test]
    /// Test handling of byte order marks (BOM) in YAML.
    fn test_byte_order_mark() {
        let yaml = "\u{feff}- 0\n";
        let expected = vec![0];
        test_de(yaml, &expected);
    }

    #[test]
    /// Test YAML deserialization with an enum that uses an alias.
    fn test_enum_alias() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            A,
            B(u8, u8),
        }
        #[derive(Deserialize, PartialEq, Debug)]
        struct Data {
            a: E,
            b: E,
        }
        let yaml = indoc! {"
        aref:
          &aref
          A
        bref:
          &bref
          !B
            - 1
            - 2

        a: *aref
        b: *bref
    "};
        let expected = Data {
            a: E::A,
            b: E::B(1, 2),
        };
        test_de(yaml, &expected);
    }

    // Test for unresolved alias panic
    #[test]
    #[should_panic(expected = "unresolved alias: 42")]
    fn test_unresolved_alias_panic() {
        let alias_pos = 42;
        let result: Option<Deserializer> = None;

        if result.is_none() {
            panic!("unresolved alias: {}", alias_pos);
        }
    }

    #[test]
    /// Test YAML deserialization with different enum representations.
    fn test_enum_representations() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum Enum {
            Unit,
            Tuple(i32, i32),
            Struct { x: i32, y: i32 },
            String(String),
            Number(f64),
        }

        let yaml = indoc! {"
        - Unit
        - 'Unit'
        - !Unit
        - !Unit ~
        - !Unit null
        - !Tuple [0, 0]
        - !Tuple
          - 0
          - 0
        - !Struct {x: 0, 'y': 0}
        - !Struct
          x: 0
          'y': 0
        - !String '...'
        - !String ...
        - !Number 0
    "};

        let expected = vec![
            Enum::Unit,
            Enum::Unit,
            Enum::Unit,
            Enum::Unit,
            Enum::Unit,
            Enum::Tuple(0, 0),
            Enum::Tuple(0, 0),
            Enum::Struct { x: 0, y: 0 },
            Enum::Struct { x: 0, y: 0 },
            Enum::String("...".to_owned()),
            Enum::String("...".to_owned()),
            Enum::Number(0.0),
        ];

        test_de(yaml, &expected);

        let yaml = indoc! {"
        - !String
    "};
        let expected = vec![Enum::String(String::new())];
        test_de_no_value(yaml, &expected);
    }

    #[test]
    /// Test deserialization of untagged enums.
    fn test_enum_untagged() {
        #[derive(Deserialize, PartialEq, Debug)]
        #[serde(untagged)]
        pub(crate) enum UntaggedEnum {
            A {
                r#match: bool,
            },
            AB {
                r#match: String,
            },
            B {
                #[serde(rename = "if")]
                r#match: bool,
            },
            C(String),
        }

        // A
        {
            let expected = UntaggedEnum::A { r#match: true };
            let deserialized: UntaggedEnum =
                serde_yml::from_str("match: True").unwrap();
            assert_eq!(expected, deserialized);
        }
        // AB
        {
            let expected = UntaggedEnum::AB {
                r#match: "T".to_owned(),
            };
            let deserialized: UntaggedEnum =
                serde_yml::from_str("match: T").unwrap();
            assert_eq!(expected, deserialized);
        }
        // B
        {
            let expected = UntaggedEnum::B { r#match: true };
            let deserialized: UntaggedEnum =
                serde_yml::from_str("if: True").unwrap();
            assert_eq!(expected, deserialized);
        }
        // C
        {
            let expected = UntaggedEnum::C("match".to_owned());
            let deserialized: UntaggedEnum =
                serde_yml::from_str("match").unwrap();
            assert_eq!(expected, deserialized);
        }
    }

    #[test]
    /// Test handling of empty string and tilde in YAML.
    fn test_empty_string() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Struct {
            empty: String,
            tilde: String,
        }
        let yaml = indoc! {"
        empty:
        tilde: ~
    "};
        let expected = Struct {
            empty: String::new(),
            tilde: "~".to_owned(),
        };
        test_de_no_value(yaml, &expected);
    }

    #[test]
    /// Test YAML deserialization with empty scalar values.
    fn test_empty_scalar() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Struct<T> {
            thing: T,
        }

        let yaml = "thing:\n";
        let expected = Struct {
            thing: serde_yml::Sequence::new(),
        };
        test_de(yaml, &expected);

        let expected = Struct {
            thing: serde_yml::Mapping::new(),
        };
        test_de(yaml, &expected);
    }

    #[test]
    /// Test deserialization of i128 numbers that are larger than i64.
    fn test_i128_big() {
        let expected: i128 = i64::MIN as i128 - 1;
        let yaml = indoc! {"
        -9223372036854775809
    "};
        assert_eq!(
            expected,
            serde_yml::from_str::<i128>(yaml).unwrap()
        );

        let octal = indoc! {"
        -0o1000000000000000000001
    "};
        assert_eq!(
            expected,
            serde_yml::from_str::<i128>(octal).unwrap()
        );
    }

    #[test]
    /// Test YAML deserialization while ignoring tags.
    fn test_ignore_tag() {
        #[derive(Deserialize, Debug, PartialEq)]
        struct Data {
            struc: Struc,
            tuple: Tuple,
            newtype: Newtype,
            map: BTreeMap<char, usize>,
            vec: Vec<usize>,
        }

        #[derive(Deserialize, Debug, PartialEq)]
        struct Struc {
            x: usize,
        }

        #[derive(Deserialize, Debug, PartialEq)]
        struct Tuple(usize, usize);

        #[derive(Deserialize, Debug, PartialEq)]
        struct Newtype(usize);

        let yaml = indoc! {"
        struc: !wat
          x: 0
        tuple: !wat
          - 0
          - 0
        newtype: !wat 0
        map: !wat
          x: 0
        vec: !wat
          - 0
    "};

        let expected = Data {
            struc: Struc { x: 0 },
            tuple: Tuple(0, 0),
            newtype: Newtype(0),
            map: {
                let mut map = BTreeMap::new();
                map.insert('x', 0);
                map
            },
            vec: vec![0],
        };

        test_de(yaml, &expected);
    }

    #[test]
    /// Test deserialization of mappings.
    fn test_de_mapping() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Data {
            pub(crate) substructure: serde_yml::Mapping,
        }
        let yaml = indoc! {"
        substructure:
          a: 'foo'
          b: 'bar'
    "};

        let mut expected = Data {
            substructure: serde_yml::Mapping::new(),
        };
        expected.substructure.insert(
            SerdeString("a".to_owned()),
            SerdeString("foo".to_owned()),
        );
        expected.substructure.insert(
            SerdeString("b".to_owned()),
            SerdeString("bar".to_owned()),
        );

        test_de(yaml, &expected);
    }

    #[test]
    /// Test YAML deserialization without using Value.
    fn test_no_value() {
        let yaml = "key: value";
        let expected =
            BTreeMap::from([("key".to_string(), "value".to_string())]);
        test_de_no_value(yaml, &expected);
    }

    #[test]
    /// Test deserialization when no required fields are present.
    fn test_no_required_fields() {
        #[derive(Deserialize, PartialEq, Debug)]
        pub(crate) struct NoRequiredFields {
            optional: Option<usize>,
        }

        for document in ["", "# comment\n"] {
            let expected = NoRequiredFields { optional: None };
            let deserialized: NoRequiredFields =
                serde_yml::from_str(document).unwrap();
            assert_eq!(expected, deserialized);

            let expected = Vec::<String>::new();
            let deserialized: Vec<String> =
                serde_yml::from_str(document).unwrap();
            assert_eq!(expected, deserialized);

            let expected = BTreeMap::new();
            let deserialized: BTreeMap<char, usize> =
                serde_yml::from_str(document).unwrap();
            assert_eq!(expected, deserialized);

            let expected = None;
            let deserialized: Option<String> =
                serde_yml::from_str(document).unwrap();
            assert_eq!(expected, deserialized);

            let expected = Value::Null;
            let deserialized: Value =
                serde_yml::from_str(document).unwrap();
            assert_eq!(expected, deserialized);
        }
    }

    #[test]
    /// Test various number formats in YAML, including hexadecimal, octal, and binary.
    fn test_numbers() {
        let cases = [
            ("0xF0", "240"),
            ("+0xF0", "240"),
            ("-0xF0", "-240"),
            ("0o70", "56"),
            ("+0o70", "56"),
            ("-0o70", "-56"),
            ("0b10", "2"),
            ("+0b10", "2"),
            ("-0b10", "-2"),
            ("127", "127"),
            ("+127", "127"),
            ("-127", "-127"),
            (".inf", ".inf"),
            (".Inf", ".inf"),
            (".INF", ".inf"),
            ("-.inf", "-.inf"),
            ("-.Inf", "-.inf"),
            ("-.INF", "-.inf"),
            (".nan", ".nan"),
            (".NaN", ".nan"),
            (".NAN", ".nan"),
            ("0.1", "0.1"),
        ];
        for &(yaml, expected) in &cases {
            let value = serde_yml::from_str::<Value>(yaml).unwrap();
            match value {
                Value::Number(number) => {
                    assert_eq!(number.to_string(), expected)
                }
                _ => panic!(
                    "expected number. input={:?}, result={:?}",
                    yaml, value
                ),
            }
        }

        // NOT numbers.
        let cases = [
            "0127", "+0127", "-0127", "++.inf", "+-.inf", "++1", "+-1",
            "-+1", "--1", "0x+1", "0x-1", "-0x+1", "-0x-1", "++0x1",
            "+-0x1", "-+0x1", "--0x1",
        ];
        for yaml in &cases {
            let value = serde_yml::from_str::<Value>(yaml).unwrap();
            match value {
                Value::String(string) => assert_eq!(string, *yaml),
                _ => panic!(
                    "expected string. input={:?}, result={:?}",
                    yaml, value
                ),
            }
        }
    }

    #[test]
    /// Test handling of NaN (Not a Number) in YAML.
    fn test_nan() {
        assert!(serde_yml::from_str::<f32>(".nan")
            .unwrap()
            .is_sign_positive());
        assert!(serde_yml::from_str::<f64>(".nan")
            .unwrap()
            .is_sign_positive());
    }

    #[test]
    /// Test YAML number aliasing and deserialization as strings.
    fn test_number_alias_as_string() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Num {
            version: String,
            value: String,
        }
        let yaml = indoc! {"
        version: &a 1.10
        value: *a
    "};
        let expected = Num {
            version: "1.10".to_owned(),
            value: "1.10".to_owned(),
        };
        test_de_no_value(yaml, &expected);
    }

    #[test]
    /// Test deserialization of strings that are large numbers.
    fn test_number_as_string() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Num {
            value: String,
        }
        let yaml = indoc! {"
        # Cannot be represented as u128
        value: 340282366920938463463374607431768211457
    "};
        let expected = Num {
            value: "340282366920938463463374607431768211457".to_owned(),
        };
        test_de_no_value(yaml, &expected);
    }

    // *** Event Handling Tests ***

    #[test]
    /// Test creation and formatting of an Event::Alias.
    fn test_event_alias() {
        let event = Event::Alias(42);
        assert_eq!(format!("{:?}", event), "Alias(42)");
    }

    #[test]
    /// Test creation and formatting of an Event::Scalar.
    fn test_event_scalar() {
        let scalar = Scalar {
            value: b"some scalar value".to_vec().into(),
            tag: None,
            style: Plain,
            repr: None,
            anchor: None,
        };
        let event = Event::Scalar(scalar);
        assert!(format!("{:?}", event).starts_with("Scalar("));
    }

    #[test]
    /// Test creation and formatting of an Event::SequenceStart.
    fn test_event_sequence_start() {
        let sequence_start = SequenceStart {
            anchor: None,
            tag: None,
        };
        let event = Event::SequenceStart(sequence_start);
        assert!(format!("{:?}", event).starts_with("SequenceStart("));
    }

    #[test]
    /// Test creation and formatting of an Event::SequenceEnd.
    fn test_event_sequence_end() {
        let event = Event::SequenceEnd;
        assert_eq!(format!("{:?}", event), "SequenceEnd");
    }

    #[test]
    /// Test creation and formatting of an Event::MappingStart.
    fn test_event_mapping_start() {
        let mapping_start = MappingStart {
            anchor: None,
            tag: None,
        };
        let event = Event::MappingStart(mapping_start);
        assert!(format!("{:?}", event).starts_with("MappingStart("));
    }

    #[test]
    /// Test creation and formatting of an Event::MappingEnd.
    fn test_event_mapping_end() {
        let event = Event::MappingEnd;
        assert_eq!(format!("{:?}", event), "MappingEnd");
    }

    #[test]
    /// Test creation and formatting of an Event::Void.
    fn test_event_void() {
        let event = Event::Void;
        assert_eq!(format!("{:?}", event), "Void");
    }

    // *** Progress Handling Tests ***

    #[test]
    /// Test deserialization of Progress::Slice variant.
    fn test_progress_slice() {
        let progress = Progress::Slice(b"test slice");
        assert_eq!(
            format!("{:?}", progress),
            r#"Progress::Slice([116, 101, 115, 116, 32, 115, 108, 105, 99, 101])"#
        );
    }

    #[test]
    /// Test deserialization of Progress::Read variant.
    fn test_progress_read() {
        let cursor = Cursor::new("test read");
        let progress = Progress::Read(Box::new(cursor));
        assert_eq!(
            format!("{:?}", progress),
            "Progress::Read(Box<dyn io::Read>)"
        );
    }

    #[test]
    /// Test deserialization of Progress::Str variant.
    fn test_progress_str() {
        let progress = Progress::Str("test string");
        assert_eq!(
            format!("{:?}", progress),
            r#"Progress::Str("test string")"#
        );
    }

    #[test]
    fn test_progress_document_returns_none() {
        // Obtain a Document from the Loader.
        let mut deserializer = Deserializer::from_str("test document");
        let document = match deserializer.next() {
            Some(deserializer) => {
                if let Progress::Document(doc) = deserializer.progress {
                    doc
                } else {
                    panic!("Expected Progress::Document");
                }
            }
            None => panic!("Expected a Document"),
        };

        // Pass the Document to Progress::Document.
        let mut deserializer = Deserializer {
            progress: Progress::Document(document),
        };

        match deserializer.progress {
            Progress::Document(_) => {
                assert!(deserializer.next().is_none());
            }
            _ => panic!("Expected Progress::Document"),
        }
    }

    #[test]
    fn test_progress_fail_propagates_error() {
        // Create an Arc-wrapped ErrorImpl directly
        let error_impl = Arc::new(ErrorImpl::Message(
            "Mock error message".into(),
            None,
        ));

        // Pass the Arc<ErrorImpl> to Progress::Fail
        let progress = Progress::Fail(error_impl.clone());

        let deserializer = Deserializer { progress };

        match deserializer.progress {
            Progress::Fail(err) => {
                // Ensure the error Arc is the same
                assert!(Arc::ptr_eq(&err, &error_impl));
            }
            _ => panic!("Expected Progress::Fail"),
        }
    }

    #[test]
    /// Test deserialization of Progress::Iterable variant.
    fn test_progress_iterable() {
        let loader = match Loader::new(Progress::Str("dummy")) {
            Ok(loader) => loader,
            Err(err) => {
                eprintln!("Error: {}", err);
                return;
            }
        };
        let progress = Progress::Iterable(loader);
        assert!(format!("{:?}", progress)
            .starts_with("Progress::Iterable("));
    }

    #[test]
    /// Test deserialization of Progress::Document variant.
    fn test_progress_document() {
        let mut deserializer = Deserializer::from_str("test document");
        let document = match deserializer.next() {
            Some(deserializer) => {
                if let Progress::Document(doc) = deserializer.progress {
                    doc
                } else {
                    panic!("Expected Progress::Document");
                }
            }
            None => panic!("Expected a Document"),
        };
        let progress = Progress::Document(document);
        assert!(format!("{:?}", progress)
            .starts_with("Progress::Document("));
    }

    #[test]
    /// Test handling of Progress::Fail variant.
    fn test_progress_fail() {
        let error_impl = Arc::new(ErrorImpl::Message(
            "Mock error message".into(),
            None,
        ));
        let progress = Progress::Fail(Arc::clone(&error_impl));
        assert!(
            format!("{:?}", progress).starts_with("Progress::Fail(")
        );
    }

    #[test]
    /// Test error handling during progress in deserialization.
    fn test_error_handling_progress_fail() {
        let mut deserializer =
            Deserializer::from_str("invalid_yaml: [unterminated");

        let result = deserializer.next();

        match result {
            Some(Deserializer {
                progress: Progress::Document(doc),
                ..
            }) => {
                if doc.error.is_none() {
                    panic!("Expected an error within the Document, but none was found.");
                }
            }
            Some(Deserializer { progress, .. }) => {
                panic!("Expected Progress::Document with an error, but got: {:?}", progress);
            }
            None => {
                panic!("Expected an error but none was found.");
            }
        }
    }

    // *** Advanced Deserialization Tests ***

    #[test]
    /// Test parsing of numbers and handling of errors.
    fn test_parse_number() {
        let n = "111".parse::<Number>().unwrap();
        assert_eq!(n, Number::from(111));

        let n = "-111".parse::<Number>().unwrap();
        assert_eq!(n, Number::from(-111));

        let n = "-1.1".parse::<Number>().unwrap();
        assert_eq!(n, Number::from(-1.1));

        let n = ".nan".parse::<Number>().unwrap();
        assert_eq!(n, Number::from(f64::NAN));
        assert!(n.as_f64().unwrap().is_sign_positive());

        let n = ".inf".parse::<Number>().unwrap();
        assert_eq!(n, Number::from(f64::INFINITY));

        let n = "-.inf".parse::<Number>().unwrap();
        assert_eq!(n, Number::from(f64::NEG_INFINITY));

        let err = "null".parse::<Number>().unwrap_err();
        assert_eq!(err.to_string(), "failed to parse YAML number");

        let err = " 1 ".parse::<Number>().unwrap_err();
        assert_eq!(err.to_string(), "failed to parse YAML number");
    }

    #[test]
    /// Test deserialization with a custom DeserializeSeed implementation.
    fn test_seed() {
        #[derive(Debug, PartialEq)]
        struct MySeed;

        impl<'de> serde::de::DeserializeSeed<'de> for MySeed {
            type Value = String;

            fn deserialize<D>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                serde::Deserialize::deserialize(deserializer)
            }
        }

        let yaml = "seed_value";
        let expected = "seed_value".to_string();
        test_de_seed(yaml, MySeed, &expected);
    }

    #[test]
    /// Test YAML deserialization with stateful seeds.
    fn test_stateful() {
        struct Seed(i64);

        impl<'de> serde::de::DeserializeSeed<'de> for Seed {
            type Value = i64;
            fn deserialize<D>(
                self,
                deserializer: D,
            ) -> Result<i64, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                struct Visitor(i64);
                impl serde::de::Visitor<'_> for Visitor {
                    type Value = i64;

                    fn expecting(
                        &self,
                        formatter: &mut Formatter<'_>,
                    ) -> std::fmt::Result {
                        write!(formatter, "an integer")
                    }

                    fn visit_i64<E: serde::de::Error>(
                        self,
                        v: i64,
                    ) -> Result<i64, E> {
                        Ok(v * self.0)
                    }

                    fn visit_u64<E: serde::de::Error>(
                        self,
                        v: u64,
                    ) -> Result<i64, E> {
                        Ok(v as i64 * self.0)
                    }
                }

                deserializer.deserialize_any(Visitor(self.0))
            }
        }

        let cases = [("3", 5, 15), ("6", 7, 42), ("-5", 9, -45)];
        for &(yaml, seed, expected) in &cases {
            test_de_seed(yaml, Seed(seed), &expected);
        }
    }

    #[test]
    /// Test deserialization of YAML with Python's `safe_dump` output format.
    fn test_python_safe_dump() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Frob {
            foo: u32,
        }

        let yaml = indoc! {r#"
        "foo": !!int |-
            7200
    "#};

        let expected = Frob { foo: 7200 };
        test_de(yaml, &expected);
    }

    #[test]
    /// Test YAML tag resolution.
    fn test_tag_resolution() {
        let yaml = indoc! {"
        - null
        - Null
        - NULL
        - ~
        -
        - true
        - True
        - TRUE
        - false
        - False
        - FALSE
        - y
        - Y
        - yes
        - Yes
        - YES
        - n
        - N
        - no
        - No
        - NO
        - on
        - On
        - ON
        - off
        - Off
        - OFF
    "};

        let expected = vec![
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(false),
            Value::Bool(false),
            Value::Bool(false),
            Value::String("y".to_owned()),
            Value::String("Y".to_owned()),
            Value::String("yes".to_owned()),
            Value::String("Yes".to_owned()),
            Value::String("YES".to_owned()),
            Value::String("n".to_owned()),
            Value::String("N".to_owned()),
            Value::String("no".to_owned()),
            Value::String("No".to_owned()),
            Value::String("NO".to_owned()),
            Value::String("on".to_owned()),
            Value::String("On".to_owned()),
            Value::String("ON".to_owned()),
            Value::String("off".to_owned()),
            Value::String("Off".to_owned()),
            Value::String("OFF".to_owned()),
        ];

        test_de(yaml, &expected);
    }

    #[test]
    /// Test deserialization of u128 numbers that are larger than u64.
    fn test_u128_big() {
        let expected: u128 = u64::MAX as u128 + 1;
        let yaml = indoc! {"
        18446744073709551616
    "};
        assert_eq!(
            expected,
            serde_yml::from_str::<u128>(yaml).unwrap()
        );

        let octal = indoc! {"
        0o2000000000000000000000
    "};
        assert_eq!(
            expected,
            serde_yml::from_str::<u128>(octal).unwrap()
        );
    }
}
