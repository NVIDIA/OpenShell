# yasna.rs: ASN.1 library for Rust

[![Build Status](https://github.com/qnighy/yasna.rs/actions/workflows/test.yml/badge.svg)](https://github.com/qnighy/yasna.rs/actions)
[![](https://img.shields.io/crates/v/yasna.svg)](https://crates.io/crates/yasna)

This is a Rust library for reading and writing ASN.1 data.

- [crates.io/crates/yasna](https://crates.io/crates/yasna)
- [Documentation](https://qnighy.github.io/yasna.rs/yasna/index.html)

Since this library is at an early stage, the APIs are subject to change. However, `BERReader` and `DERWriter` functionalities are getting stable.

## Serialization/Construction

Serialization in DER (Distinguished Encoding Rules) is supported. It can also be used for serialization in BER (Basic Encoding Rules).

```rust
fn main() {
    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_i64(10);
            writer.next().write_bool(true);
            return Ok(());
        })
    });
    println!("(10, true) = {:?}", der);
}
```

Currently, these datatypes are supported:

- BOOLEAN, INTEGER, BITSTRING, OCTETSTRING, NULL, OBJECT IDENTIFIER,
- SEQUENCE, SEQUENCE OF, SET, SET OF, CHOICE,
- UTF8String, NumericString, PrintableString, VisibleString, IA5String, BMPString,
- UTCTime, GeneralizedTime,
- Explicitly/Implicitly tagged types,
- DEFAULT/OPTIONAL in SEQUENCE/SET.

These datatypes are *not* supported:

- REAL
- TeletexString, VideotexString, GraphicString, GeneralString, UniversalString,
- TIME, DATE, TIME-OF-DAY, DATE-TIME, DURATION.

## Deserialization/Parsing

Deserialization in BER (Basic Encoding Rules) or DER (Distinguished Encoding Rules) is supported.

```rust
fn main() {
    let asn = yasna::parse_der(&[48, 6, 2, 1, 10, 1, 1, 255], |reader| {
        reader.read_sequence(|reader| {
            let i = reader.next().read_i64()?;
            let b = reader.next().read_bool()?;
            return Ok((i, b));
        })
    }).unwrap();
    println!("{:?} = [48, 6, 2, 1, 10, 1, 1, 255]", asn);
}
```

Currently, these datatypes are supported:

- BOOLEAN, INTEGER, BITSTRING, OCTETSTRING, NULL, OBJECT IDENTIFIER,
- SEQUENCE, SEQUENCE OF, SET, SET OF, CHOICE,
- UTF8String, NumericString, PrintableString, VisibleString, IA5String, BMPString,
- UTCTime, GeneralizedTime,
- Explicitly/Implicitly tagged types,
- DEFAULT/OPTIONAL in SEQUENCE.

These datatypes are *not* supported:

- REAL
- TeletexString, VideotexString, GraphicString, GeneralString, UniversalString,
- TIME, DATE, TIME-OF-DAY, DATE-TIME, DURATION.
- DEFAULT/OPTIONAL in SET.

## Other encodings

This library is currently specialized for BER (Basic Encoding Rules) and DER (Distinguished Encoding Rules). Other encodings such as CER (Canonical Encoding Rules), PER (Packed Encoding Rules), and XER (XML Encoding Rules) are currently out of scope.

## Streaming

This library is currently specialized for on-memory serialization/deserialization. There are no plans for streaming ones.

## Compatibility

The minimum supported Rust version (MSRV) of `yasna.rs` is Rust 1.36.0.
Optional feature flags that enable interoperability with third-party crates (e.g. `time`) follow the policy of that crate if stricter.

## License

This library is distributed under MIT/Apache-2.0 dual license.
