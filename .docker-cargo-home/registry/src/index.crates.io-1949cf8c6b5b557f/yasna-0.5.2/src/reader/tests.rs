// Copyright 2016 Masaki Hara
// Copyright 2017 Fortanix, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(feature = "num-bigint")]
use num_bigint::{BigUint, BigInt};

use super::super::Tag;
use super::super::tags::TAG_SEQUENCE;
use super::*;

#[test]
fn test_der_read_bool_ok() {
    let tests : &[(bool, &[u8])] = &[
        (false, &[1, 1, 0]),
        (true, &[1, 1, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_bool()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_der_read_bool_err() {
    let tests : &[&[u8]] = &[
        &[], &[1], &[0, 0], &[0, 1, 0], &[2, 1, 0], &[33, 1, 0], &[65, 1, 0],
        &[1, 0], &[1, 2, 0, 0], &[1, 128, 1, 1, 0, 0, 0],
        &[1, 1, 1], &[1, 1, 191], &[1, 1, 254],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_bool()
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_bool_ok() {
    let tests : &[(bool, &[u8])] = &[
        (false, &[1, 1, 0]),
        (true, &[1, 1, 1]),
        (true, &[1, 1, 191]),
        (true, &[1, 1, 254]),
        (true, &[1, 1, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_bool()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_ber_read_bool_err() {
    let tests : &[&[u8]] = &[
        &[], &[1], &[0, 0], &[0, 1, 0], &[2, 1, 0], &[33, 1, 0], &[65, 1, 0],
        &[1, 0], &[1, 2, 0, 0], &[1, 128, 1, 1, 0, 0, 0],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_bool()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_i64_ok() {
    test_general_read_i64_ok(BERMode::Der);
}

#[test]
fn test_der_read_i64_err() {
    test_general_read_i64_err(BERMode::Der);
}

#[test]
fn test_ber_read_i64_ok() {
    test_general_read_i64_ok(BERMode::Ber);
}

#[test]
fn test_ber_read_i64_err() {
    test_general_read_i64_err(BERMode::Ber);
}

fn test_general_read_i64_ok(mode: BERMode) {
    let tests : &[(i64, &[u8])] = &[
        (-9223372036854775808, &[2, 8, 128, 0, 0, 0, 0, 0, 0, 0]),
        (-65537, &[2, 3, 254, 255, 255]),
        (-65536, &[2, 3, 255, 0, 0]),
        (-32769, &[2, 3, 255, 127, 255]),
        (-32768, &[2, 2, 128, 0]),
        (-129, &[2, 2, 255, 127]),
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (9223372036854775807, &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_i64()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

fn test_general_read_i64_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 9, 255, 0, 0, 0, 0, 0, 0, 0, 0],
        &[2, 9, 255, 127, 255, 255, 255, 255, 255, 255, 255],
        &[2, 9, 0, 128, 0, 0, 0, 0, 0, 0, 0],
        &[2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_i64()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_u64_ok() {
    test_general_read_u64_ok(BERMode::Der);
}

#[test]
fn test_der_read_u64_err() {
    test_general_read_u64_err(BERMode::Der);
}

#[test]
fn test_ber_read_u64_ok() {
    test_general_read_u64_ok(BERMode::Ber);
}

#[test]
fn test_ber_read_u64_err() {
    test_general_read_u64_err(BERMode::Ber);
}

fn test_general_read_u64_ok(mode: BERMode) {
    let tests : &[(u64, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (9223372036854775807, &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
        (18446744073709551615,
            &[2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_u64()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

fn test_general_read_u64_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 8, 128, 0, 0, 0, 0, 0, 0, 0], &[2, 3, 254, 255, 255],
        &[2, 3, 255, 0, 0], &[2, 3, 255, 127, 255], &[2, 2, 128, 0],
        &[2, 2, 255, 127], &[2, 1, 128], &[2, 1, 255],
        &[2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        &[2, 9, 1, 128, 0, 0, 0, 0, 0, 0, 0],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_u64()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_i32_ok() {
    test_general_read_i32_ok(BERMode::Der);
}

#[test]
fn test_der_read_i32_err() {
    test_general_read_i32_err(BERMode::Der);
}

#[test]
fn test_ber_read_i32_ok() {
    test_general_read_i32_ok(BERMode::Ber);
}

#[test]
fn test_ber_read_i32_err() {
    test_general_read_i32_err(BERMode::Ber);
}

fn test_general_read_i32_ok(mode: BERMode) {
    let tests : &[(i32, &[u8])] = &[
        (-2147483648, &[2, 4, 128, 0, 0, 0]),
        (-65537, &[2, 3, 254, 255, 255]),
        (-65536, &[2, 3, 255, 0, 0]),
        (-32769, &[2, 3, 255, 127, 255]),
        (-32768, &[2, 2, 128, 0]),
        (-129, &[2, 2, 255, 127]),
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (2147483647, &[2, 4, 127, 255, 255, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_i32()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

fn test_general_read_i32_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 5, 255, 0, 0, 0, 0],
        &[2, 5, 255, 127, 255, 255, 255],
        &[2, 5, 0, 128, 0, 0, 0],
        &[2, 5, 0, 255, 255, 255, 255],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_i32()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_u32_err() {
    test_general_read_u32_err(BERMode::Der);
}

#[test]
fn test_ber_read_u32_ok() {
    test_general_read_u32_ok(BERMode::Ber);
}

#[test]
fn test_ber_read_u32_err() {
    test_general_read_u32_err(BERMode::Ber);
}

fn test_general_read_u32_ok(mode: BERMode) {
    let tests : &[(u32, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (2147483647, &[2, 4, 127, 255, 255, 255]),
        (4294967295, &[2, 5, 0, 255, 255, 255, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_u32()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

fn test_general_read_u32_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 4, 128, 0, 0, 0], &[2, 3, 254, 255, 255], &[2, 3, 255, 0, 0],
        &[2, 3, 255, 127, 255], &[2, 2, 128, 0], &[2, 2, 255, 127],
        &[2, 1, 128], &[2, 1, 255],
        &[2, 5, 1, 0, 0, 0, 0],
        &[2, 5, 1, 128, 0, 0, 0],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_u32()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_i16_ok() {
    test_general_read_i16_ok(BERMode::Der);
}

#[test]
fn test_der_read_i16_err() {
    test_general_read_i16_err(BERMode::Der);
}

#[test]
fn test_ber_read_i16_ok() {
    test_general_read_i16_ok(BERMode::Ber);
}

#[test]
fn test_ber_read_i16_err() {
    test_general_read_i16_err(BERMode::Ber);
}

fn test_general_read_i16_ok(mode: BERMode) {
    let tests : &[(i16, &[u8])] = &[
        (-32768, &[2, 2, 128, 0]),
        (-129, &[2, 2, 255, 127]),
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_i16()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

fn test_general_read_i16_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 3, 255, 0, 0], &[2, 3, 255, 127, 255],
        &[2, 3, 0, 128, 0], &[2, 3, 0, 255, 255],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_i16()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_u16_ok() {
    test_general_read_u16_ok(BERMode::Der);
}

#[test]
fn test_der_read_u16_err() {
    test_general_read_u16_err(BERMode::Der);
}

#[test]
fn test_ber_read_u16_ok() {
    test_general_read_u16_ok(BERMode::Ber);
}

#[test]
fn test_ber_read_u16_err() {
    test_general_read_u16_err(BERMode::Ber);
}

fn test_general_read_u16_ok(mode: BERMode) {
    let tests : &[(u16, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (65535, &[2, 3, 0, 255, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_u16()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

fn test_general_read_u16_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 2, 128, 0], &[2, 2, 255, 127], &[2, 1, 128], &[2, 1, 255],
        &[2, 3, 1, 0, 0], &[2, 3, 1, 128, 0],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_u16()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_i8_ok() {
    test_general_read_i8_ok(BERMode::Der);
}

#[test]
fn test_der_read_i8_err() {
    test_general_read_i8_err(BERMode::Der);
}

#[test]
fn test_ber_read_i8_ok() {
    test_general_read_i8_ok(BERMode::Ber);
}

#[test]
fn test_ber_read_i8_err() {
    test_general_read_i8_err(BERMode::Ber);
}

fn test_general_read_i8_ok(mode: BERMode) {
    let tests : &[(i8, &[u8])] = &[
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_i8()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

fn test_general_read_i8_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 2, 255, 0], &[2, 2, 255, 127], &[2, 2, 0, 128], &[2, 2, 0, 255],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_i8()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_u8_ok() {
    test_general_read_u8_ok(BERMode::Der);
}

#[test]
fn test_der_read_u8_err() {
    test_general_read_u8_err(BERMode::Der);
}

#[test]
fn test_ber_read_u8_ok() {
    test_general_read_u8_ok(BERMode::Ber);
}

#[test]
fn test_ber_read_u8_err() {
    test_general_read_u8_err(BERMode::Ber);
}

fn test_general_read_u8_ok(mode: BERMode) {
    let tests : &[(u8, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (255, &[2, 2, 0, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_u8()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

fn test_general_read_u8_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 1, 128], &[2, 1, 255],
        &[2, 2, 1, 0], &[2, 2, 1, 128],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_u8()
        }).unwrap_err();
    }
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_der_read_bigint_ok() {
    test_general_read_bigint_ok(BERMode::Der);
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_der_read_bigint_err() {
    test_general_read_bigint_err(BERMode::Der);
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_ber_read_bigint_ok() {
    test_general_read_bigint_ok(BERMode::Ber);
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_ber_read_bigint_err() {
    test_general_read_bigint_err(BERMode::Ber);
}

#[cfg(feature = "num-bigint")]
fn test_general_read_bigint_ok(mode: BERMode) {
    use num_traits::FromPrimitive;
    let tests : &[(i64, &[u8])] = &[
        (-9223372036854775808, &[2, 8, 128, 0, 0, 0, 0, 0, 0, 0]),
        (-65537, &[2, 3, 254, 255, 255]),
        (-65536, &[2, 3, 255, 0, 0]),
        (-32769, &[2, 3, 255, 127, 255]),
        (-32768, &[2, 2, 128, 0]),
        (-129, &[2, 2, 255, 127]),
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (9223372036854775807, &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_bigint()
        }).unwrap();
        assert_eq!(value, BigInt::from_i64(evalue).unwrap());
    }

    let tests : &[(BigInt, &[u8])] = &[
        (BigInt::parse_bytes(
            b"1234567890123456789012345678901234567890", 10).unwrap(),
            &[2, 17, 3, 160, 201, 32, 117, 192, 219,
            243, 184, 172, 188, 95, 150, 206, 63, 10, 210]),
        (BigInt::parse_bytes(
            b"-1234567890123456789012345678901234567890", 10).unwrap(),
            &[2, 17, 252, 95, 54, 223, 138, 63, 36,
            12, 71, 83, 67, 160, 105, 49, 192, 245, 46]),
        (BigInt::parse_bytes(b"-18446744073709551616", 10).unwrap(),
            &[2, 9, 255, 0, 0, 0, 0, 0, 0, 0, 0]),
        (BigInt::parse_bytes(b"-9223372036854775809", 10).unwrap(),
            &[2, 9, 255, 127, 255, 255, 255, 255, 255, 255, 255]),
        (BigInt::parse_bytes(b"9223372036854775808", 10).unwrap(),
            &[2, 9, 0, 128, 0, 0, 0, 0, 0, 0, 0]),
        (BigInt::parse_bytes(b"18446744073709551615", 10).unwrap(),
            &[2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(ref evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_bigint()
        }).unwrap();
        assert_eq!(&value, evalue);
    }
}

#[cfg(feature = "num-bigint")]
fn test_general_read_bigint_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_bigint()
        }).unwrap_err();
    }
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_der_read_biguint_ok() {
    test_general_read_biguint_ok(BERMode::Der);
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_der_read_biguint_err() {
    test_general_read_biguint_err(BERMode::Der);
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_ber_read_biguint_ok() {
    test_general_read_biguint_ok(BERMode::Ber);
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_ber_read_biguint_err() {
    test_general_read_biguint_err(BERMode::Ber);
}

#[cfg(feature = "num-bigint")]
fn test_general_read_biguint_ok(mode: BERMode) {
    use num_traits::FromPrimitive;
    let tests : &[(u64, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (9223372036854775807, &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
        (18446744073709551615,
            &[2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_biguint()
        }).unwrap();
        assert_eq!(value, BigUint::from_u64(evalue).unwrap());
    }

    let tests : &[(BigUint, &[u8])] = &[
        (BigUint::parse_bytes(
            b"1234567890123456789012345678901234567890", 10).unwrap(),
            &[2, 17, 3, 160, 201, 32, 117, 192, 219,
            243, 184, 172, 188, 95, 150, 206, 63, 10, 210]),
        (BigUint::parse_bytes(b"9223372036854775808", 10).unwrap(),
            &[2, 9, 0, 128, 0, 0, 0, 0, 0, 0, 0]),
        (BigUint::parse_bytes(b"18446744073709551615", 10).unwrap(),
            &[2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(ref evalue, data) in tests {
        let value = parse_ber_general(data, mode, |reader| {
            reader.read_biguint()
        }).unwrap();
        assert_eq!(&value, evalue);
    }
}

#[cfg(feature = "num-bigint")]
fn test_general_read_biguint_err(mode: BERMode) {
    let tests : &[&[u8]] = &[
        &[], &[2], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[34, 1, 0], &[66, 1, 0],
        &[2, 0], &[2, 128, 2, 1, 0, 0, 0], &[2, 2, 0], &[2, 1, 1, 1],
        &[2, 2, 255, 128], &[2, 2, 255, 200], &[2, 2, 0, 127], &[2, 2, 0, 56],
        &[2, 3, 255, 151, 55], &[2, 3, 0, 1, 2],
        &[2, 8, 128, 0, 0, 0, 0, 0, 0, 0], &[2, 3, 254, 255, 255],
        &[2, 3, 255, 0, 0], &[2, 3, 255, 127, 255], &[2, 2, 128, 0],
        &[2, 2, 255, 127], &[2, 1, 128], &[2, 1, 255],
        &[2, 17, 252, 95, 54, 223, 138, 63, 36,
            12, 71, 83, 67, 160, 105, 49, 192, 245, 46],
        &[2, 9, 255, 0, 0, 0, 0, 0, 0, 0, 0],
        &[2, 9, 255, 127, 255, 255, 255, 255, 255, 255, 255],
    ];
    for &data in tests {
        parse_ber_general(data, mode, |reader| {
            reader.read_biguint()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_bytes_ok() {
    let tests : &[(&[u8], &[u8])] = &[
        (&[1, 0, 100, 255], &[4, 4, 1, 0, 100, 255]),
        (&[], &[4, 0]),
        (&[4, 4, 4, 4], &[4, 4, 4, 4, 4, 4]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_bytes()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_der_read_bytes_err() {
    let tests : &[&[u8]] = &[
        &[], &[4], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[36, 1, 0], &[68, 1, 0],
        &[4, 4, 0], &[4, 1, 1, 1], &[36, 128, 1, 0, 0],
        &[36, 128, 0, 0],
        &[36, 128, 4, 2, 12, 34, 0, 0],
        &[36, 128, 36, 128, 4, 3, 12, 34, 56, 0, 0, 0, 0],
        &[36, 128, 36, 128, 36, 128, 36, 128, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[36, 128, 4, 1, 2, 36, 128, 4, 2, 3, 1, 0, 0, 0, 0],
        &[36, 0],
        &[36, 4, 4, 2, 12, 34],
        &[36, 128, 36, 5, 4, 3, 12 ,34, 56, 0, 0],
        &[36, 9, 36, 128, 4, 3, 12, 34, 56, 0, 0],
        &[36, 7, 36, 5, 4, 3, 12 ,34, 56],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_bytes()
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_bytes_ok() {
    let tests : &[(&[u8], &[u8])] = &[
        (&[1, 0, 100, 255], &[4, 4, 1, 0, 100, 255]),
        (&[], &[4, 0]),
        (&[4, 4, 4, 4], &[4, 4, 4, 4, 4, 4]),
        (&[], &[36, 128, 0, 0]),
        (&[12, 34], &[36, 128, 4, 2, 12, 34, 0, 0]),
        (&[12, 34, 56], &[36, 128, 36, 128, 4, 3, 12, 34, 56, 0, 0, 0, 0]),
        (&[], &[36, 128, 36, 128, 36, 128, 36,
             128, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        (&[2, 3, 1], &[36, 128, 4, 1, 2, 36, 128, 4, 2, 3, 1, 0, 0, 0, 0]),
        (&[], &[36, 0]),
        (&[12, 34], &[36, 4, 4, 2, 12, 34]),
        (&[12, 34, 56], &[36, 128, 36, 5, 4, 3, 12 ,34, 56, 0, 0]),
        (&[12, 34, 56], &[36, 9, 36, 128, 4, 3, 12, 34, 56, 0, 0]),
        (&[12, 34, 56], &[36, 7, 36, 5, 4, 3, 12 ,34, 56]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_bytes()
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_ber_read_bytes_err() {
    let tests : &[&[u8]] = &[
        &[], &[4], &[0, 0], &[0, 1, 0], &[1, 1, 0], &[36, 1, 0], &[68, 1, 0],
        &[4, 4, 0], &[4, 1, 1, 1], &[4, 128, 1, 0, 0],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_bytes()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_null_ok() {
    let value = parse_der(&[5, 0], |reader| {
        reader.read_null()
    }).unwrap();
    assert_eq!(value, ());
}

#[test]
fn test_der_read_null_err() {
    let tests : &[&[u8]] = &[
        &[], &[5], &[0, 0], &[0, 1, 0], &[2, 1, 0], &[37, 0], &[69, 0],
        &[5, 128, 0], &[37, 128, 0], &[5, 1, 0], &[5, 2, 0, 0],
        &[5, 1], &[5, 0, 1],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_null()
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_null_ok() {
    let value = parse_ber(&[5, 0], |reader| {
        reader.read_null()
    }).unwrap();
    assert_eq!(value, ());
}

#[test]
fn test_ber_read_null_err() {
    let tests : &[&[u8]] = &[
        &[], &[5], &[0, 0], &[0, 1, 0], &[2, 1, 0], &[37, 0], &[69, 0],
        &[5, 128, 0], &[37, 128, 0], &[5, 1, 0], &[5, 2, 0, 0],
        &[5, 1], &[5, 0, 1],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_null()
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_sequence_ok() {
    let tests : &[((i64, bool), &[u8])] = &[
        ((10, true), &[48, 6, 2, 1, 10, 1, 1, 255]),
        ((266, true), &[48, 7, 2, 2, 1, 10, 1, 1, 255]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_sequence(|reader| {
                let i = reader.next().read_i64()?;
                let b = reader.next().read_bool()?;
                return Ok((i, b));
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }

    let tests : &[((), &[u8])] = &[
        ((), &[48, 0]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_sequence(|_| {
                Ok(())
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_der_read_sequence_err() {
    let tests : &[&[u8]] = &[
        &[], &[48], &[0, 0], &[0, 1, 0],
        &[49, 6, 2, 1, 10, 1, 1, 255],
        &[16, 6, 2, 1, 10, 1, 1, 255],
        &[112, 6, 2, 1, 10, 1, 1, 255],
        &[48, 6, 2, 1, 10, 1, 1, 255, 0],
        &[48, 6, 2, 2, 1, 10, 1, 1, 255],
        &[48, 7, 2, 1, 10, 1, 1, 255, 0],
        &[48, 7, 2, 1, 10, 1, 1, 255],
        &[48, 8, 48, 6, 2, 1, 10, 1, 1, 255],
        &[49, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[16, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[112, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[48, 128, 2, 1, 10, 1, 1, 255, 0, 0, 0],
        &[48, 128, 48, 6, 2, 1, 10, 1, 1, 255, 0, 0],
        &[48, 10, 48, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[48, 128, 48, 128, 2, 1, 10, 1, 1, 255, 0, 0, 0, 0],
        &[48, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[48, 128, 2, 2, 1, 10, 1, 1, 255, 0, 0],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_sequence(|reader| {
                let i = reader.next().read_i64()?;
                let b = reader.next().read_bool()?;
                return Ok((i, b));
            })
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_tagged_der_err() {
    let tests : &[&[u8]] = &[
        &[], &[48], &[0, 0], &[0, 1, 0],
        &[48, 6, 2, 1, 10, 1, 1, 255, 0],
        &[48, 6, 2, 2, 1, 10, 1, 1, 255],
        &[48, 7, 2, 1, 10, 1, 1, 255],
        &[48, 128, 2, 1, 10, 1, 1, 255, 0, 0, 0],

        // Otherwise valid indefinite-length encodings
        &[48, 128, 48, 6, 2, 1, 10, 1, 1, 255, 0, 0],
        &[48, 128, 48, 128, 2, 1, 10, 1, 1, 255, 0, 0, 0, 0],
        &[48, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[48, 128, 2, 2, 1, 10, 1, 1, 255, 0, 0],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_tagged_der()
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_sequence_ok() {
    let tests : &[((i64, bool),
                  TaggedDerValue,
                  &[u8])] = &[
        // Definite-length encoding
        ((10, true),
            TaggedDerValue::from_tag_and_bytes(
                TAG_SEQUENCE,
                [2, 1, 10, 1, 1, 255].to_vec()),
            &[48, 6, 2, 1, 10, 1, 1, 255]),
        // Definite-length encoding
        ((266, true),
            TaggedDerValue::from_tag_and_bytes(
                TAG_SEQUENCE,
                [2, 2, 1, 10, 1, 1, 255].to_vec()),
            &[48, 7, 2, 2, 1, 10, 1, 1, 255]),
        // Indefinite-length encoding
        ((10, true),
            TaggedDerValue::from_tag_and_bytes(
                TAG_SEQUENCE,
                [2, 1, 10, 1, 1, 255, 0, 0].to_vec()),
            &[48, 128, 2, 1, 10, 1, 1, 255, 0, 0]),
        // Indefinite-length encoding
        ((266, true),
            TaggedDerValue::from_tag_and_bytes(
                TAG_SEQUENCE,
                [2, 2, 1, 10, 1, 1, 255, 0, 0].to_vec()),
            &[48, 128, 2, 2, 1, 10, 1, 1, 255, 0, 0]),
    ];
    for &(evalue, ref ervalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_sequence(|reader| {
                let i = reader.next().read_i64()?;
                let b = reader.next().read_bool()?;
                return Ok((i, b));
            })
        }).unwrap();
        assert_eq!(value, evalue);
        let rvalue = parse_ber(data, |reader| {
            reader.read_tagged_der()
        }).unwrap();
        assert_eq!(&rvalue, ervalue);
    }

    let tests : &[((), &[u8])] = &[
        ((), &[48, 0]),
        ((), &[48, 128, 0, 0]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_sequence(|_| {
                Ok(())
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_ber_read_sequence_err() {
    let tests : &[&[u8]] = &[
        &[], &[48], &[0, 0], &[0, 1, 0],
        &[49, 6, 2, 1, 10, 1, 1, 255],
        &[16, 6, 2, 1, 10, 1, 1, 255],
        &[112, 6, 2, 1, 10, 1, 1, 255],
        &[48, 6, 2, 1, 10, 1, 1, 255, 0],
        &[48, 6, 2, 2, 1, 10, 1, 1, 255],
        &[48, 7, 2, 1, 10, 1, 1, 255, 0],
        &[48, 7, 2, 1, 10, 1, 1, 255],
        &[48, 8, 48, 6, 2, 1, 10, 1, 1, 255],
        &[49, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[16, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[112, 128, 2, 1, 10, 1, 1, 255, 0, 0],
        &[48, 128, 2, 1, 10, 1, 1, 255, 0, 0, 0],
        &[48, 128, 48, 6, 2, 1, 10, 1, 1, 255, 0, 0],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_sequence(|reader| {
                let i = reader.next().read_i64()?;
                let b = reader.next().read_bool()?;
                return Ok((i, b));
            })
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_set_ok() {
    let tests : &[((i64, Vec<u8>, i64, Vec<u8>), &[u8])] = &[
        ((456789, b"Foo".to_vec(), 456790, b"Bar".to_vec()), &[
        49, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111]),
    ];
    for &(ref evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_set(|reader| {
                let a = reader.next(&[Tag::context(28)])?
                    .read_tagged_implicit(Tag::context(28), |reader| {
                    reader.read_i64()
                })?;
                let b = reader.next(&[Tag::context(345678)])?
                    .read_tagged(Tag::context(345678), |reader| {
                    reader.read_bytes()
                })?;
                let c = reader.next(&[Tag::context(27)])?
                    .read_tagged(Tag::context(27), |reader| {
                    reader.read_i64()
                })?;
                let d = reader.next(&[Tag::context(345677)])?
                    .read_tagged(Tag::context(345677), |reader| {
                    reader.read_bytes()
                })?;
                return Ok((a, b, c, d));
            })
        }).unwrap();
        assert_eq!(&value, evalue);
    }
}

#[test]
fn test_der_read_set_err() {
    let tests : &[&[u8]] = &[
        &[], &[49], &[0, 0], &[0, 1, 0],
        &[17, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[113, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[48, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[49, 33, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[49, 33, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111, 0],
        &[49, 31, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[49, 31, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111],
        &[49, 22, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114],
        &[49, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111,
        191, 149, 140, 79, 5, 4, 3, 70, 111, 111],
        &[49, 128, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
            77, 5, 4, 3, 66, 97, 114, 191, 149,
            140, 78, 5, 4, 3, 70, 111, 111, 0, 0],
        &[49, 32, 156, 3, 6, 248, 85, 187, 5, 2, 3, 6, 248, 86, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[49, 32, 187, 5, 2, 3, 6, 248, 86, 191, 149, 140, 77, 5, 4, 3, 66, 97,
        114, 156, 3, 6, 248, 85, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[49, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        78, 5, 4, 3, 70, 111, 111, 191, 149, 140, 77, 5, 4, 3, 66, 97, 114],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_set(|reader| {
                let a = reader.next(&[Tag::context(28)])?
                    .read_tagged_implicit(Tag::context(28), |reader| {
                    reader.read_i64()
                })?;
                let b = reader.next(&[Tag::context(345678)])?
                    .read_tagged(Tag::context(345678), |reader| {
                    reader.read_bytes()
                })?;
                let c = reader.next(&[Tag::context(27)])?
                    .read_tagged(Tag::context(27), |reader| {
                    reader.read_i64()
                })?;
                let d = reader.next(&[Tag::context(345677)])?
                    .read_tagged(Tag::context(345677), |reader| {
                    reader.read_bytes()
                })?;
                return Ok((a, b, c, d));
            })
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_set_ok() {
    let tests : &[((i64, Vec<u8>, i64, Vec<u8>), &[u8])] = &[
        ((456789, b"Foo".to_vec(), 456790, b"Bar".to_vec()), &[
        49, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111]),
        ((456789, b"Foo".to_vec(), 456790, b"Bar".to_vec()), &[
        49, 128, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
            77, 5, 4, 3, 66, 97, 114, 191, 149,
            140, 78, 5, 4, 3, 70, 111, 111, 0, 0]),
        ((456789, b"Foo".to_vec(), 456790, b"Bar".to_vec()), &[
        49, 32, 156, 3, 6, 248, 85, 187, 5, 2, 3, 6, 248, 86, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111]),
        ((456789, b"Foo".to_vec(), 456790, b"Bar".to_vec()), &[
        49, 32, 187, 5, 2, 3, 6, 248, 86, 191, 149, 140, 77, 5, 4, 3, 66, 97,
        114, 156, 3, 6, 248, 85, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111]),
        ((456789, b"Foo".to_vec(), 456790, b"Bar".to_vec()), &[
        49, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        78, 5, 4, 3, 70, 111, 111, 191, 149, 140, 77, 5, 4, 3, 66, 97, 114]),
    ];
    for &(ref evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_set(|reader| {
                let a = reader.next(&[Tag::context(28)])?
                    .read_tagged_implicit(Tag::context(28), |reader| {
                    reader.read_i64()
                })?;
                let b = reader.next(&[Tag::context(345678)])?
                    .read_tagged(Tag::context(345678), |reader| {
                    reader.read_bytes()
                })?;
                let c = reader.next(&[Tag::context(27)])?
                    .read_tagged(Tag::context(27), |reader| {
                    reader.read_i64()
                })?;
                let d = reader.next(&[Tag::context(345677)])?
                    .read_tagged(Tag::context(345677), |reader| {
                    reader.read_bytes()
                })?;
                return Ok((a, b, c, d));
            })
        }).unwrap();
        assert_eq!(&value, evalue);
    }
}

#[test]
fn test_ber_read_set_err() {
    let tests : &[&[u8]] = &[
        &[], &[49], &[0, 0], &[0, 1, 0],
        &[17, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[113, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[48, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[49, 33, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[49, 33, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111, 0],
        &[49, 31, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111],
        &[49, 31, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111],
        &[49, 22, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114],
        &[49, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111,
        191, 149, 140, 79, 5, 4, 3, 70, 111, 111],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_set(|reader| {
                let a = reader.next(&[Tag::context(28)])?
                    .read_tagged_implicit(Tag::context(28), |reader| {
                    reader.read_i64()
                })?;
                let b = reader.next(&[Tag::context(345678)])?
                    .read_tagged(Tag::context(345678), |reader| {
                    reader.read_bytes()
                })?;
                let c = reader.next(&[Tag::context(27)])?
                    .read_tagged(Tag::context(27), |reader| {
                    reader.read_i64()
                })?;
                let d = reader.next(&[Tag::context(345677)])?
                    .read_tagged(Tag::context(345677), |reader| {
                    reader.read_bytes()
                })?;
                return Ok((a, b, c, d));
            })
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_set_of_ok() {
    use std::collections::HashSet;
    let tests : &[(&[i64], &[u8])] = &[
        (&[-129, -128, 127, 128], &[
            49, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127]),
        (&[-128, 127, 128], &[
            49, 10, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128]),
        (&[-129, -128, 127, 128, 32768], &[
            49, 19, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127,
            2, 3, 0, 128, 0]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.collect_set_of(|reader| {
                reader.read_i64()
            })
        }).unwrap();
        let value_set = value.iter().collect::<HashSet<_>>();
        let evalue_set = evalue.iter().collect::<HashSet<_>>();
        assert_eq!(value_set, evalue_set);
    }
}

#[test]
fn test_der_read_set_of_err() {
    let tests : &[&[u8]] = &[
        &[], &[49], &[0, 0], &[0, 1, 0],
        &[17, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[113, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[48, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[49, 15, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[49, 15, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127, 0],
        &[49, 13, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[49, 13, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255],
        &[49, 128, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127, 0, 0],
        &[49, 14, 2, 1, 128, 2, 1, 127, 2, 2, 0, 128, 2, 2, 255, 127],
        &[49, 14, 2, 1, 127, 2, 2, 0, 128, 2, 1, 128, 2, 2, 255, 127],
        &[49, 14, 2, 1, 127, 2, 1, 128, 2, 2, 255, 127, 2, 2, 0, 128],
        &[49, 14, 2, 2, 255, 127, 2, 1, 128, 2, 2, 0, 128, 2, 1, 127],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_set(|reader| {
                let a = reader.next(&[Tag::context(28)])?
                    .read_tagged_implicit(Tag::context(28), |reader| {
                    reader.read_i64()
                })?;
                let b = reader.next(&[Tag::context(345678)])?
                    .read_tagged(Tag::context(345678), |reader| {
                    reader.read_bytes()
                })?;
                let c = reader.next(&[Tag::context(27)])?
                    .read_tagged(Tag::context(27), |reader| {
                    reader.read_i64()
                })?;
                let d = reader.next(&[Tag::context(345677)])?
                    .read_tagged(Tag::context(345677), |reader| {
                    reader.read_bytes()
                })?;
                return Ok((a, b, c, d));
            })
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_set_of_ok() {
    use std::collections::HashSet;
    let tests : &[(&[i64], &[u8])] = &[
        (&[-129, -128, 127, 128], &[
            49, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127]),
        (&[-128, 127, 128], &[
            49, 10, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128]),
        (&[-129, -128, 127, 128, 32768], &[
            49, 19, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127,
            2, 3, 0, 128, 0]),
        (&[-129, -128, 127, 128], &[
            49, 128, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127,
            0, 0]),
        (&[-129, -128, 127, 128], &[
            49, 14, 2, 1, 128, 2, 1, 127, 2, 2, 0, 128, 2, 2, 255, 127]),
        (&[-129, -128, 127, 128], &[
            49, 14, 2, 1, 127, 2, 2, 0, 128, 2, 1, 128, 2, 2, 255, 127]),
        (&[-129, -128, 127, 128], &[
            49, 14, 2, 1, 127, 2, 1, 128, 2, 2, 255, 127, 2, 2, 0, 128]),
        (&[-129, -128, 127, 128], &[
            49, 14, 2, 2, 255, 127, 2, 1, 128, 2, 2, 0, 128, 2, 1, 127]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.collect_set_of(|reader| {
                reader.read_i64()
            })
        }).unwrap();
        let value_set = value.iter().collect::<HashSet<_>>();
        let evalue_set = evalue.iter().collect::<HashSet<_>>();
        assert_eq!(value_set, evalue_set);
    }
}

#[test]
fn test_ber_read_set_of_err() {
    let tests : &[&[u8]] = &[
        &[], &[49], &[0, 0], &[0, 1, 0],
        &[17, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[113, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[48, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[49, 15, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[49, 15, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127, 0],
        &[49, 13, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127],
        &[49, 13, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_set(|reader| {
                let a = reader.next(&[Tag::context(28)])?
                    .read_tagged_implicit(Tag::context(28), |reader| {
                    reader.read_i64()
                })?;
                let b = reader.next(&[Tag::context(345678)])?
                    .read_tagged(Tag::context(345678), |reader| {
                    reader.read_bytes()
                })?;
                let c = reader.next(&[Tag::context(27)])?
                    .read_tagged(Tag::context(27), |reader| {
                    reader.read_i64()
                })?;
                let d = reader.next(&[Tag::context(345677)])?
                    .read_tagged(Tag::context(345677), |reader| {
                    reader.read_bytes()
                })?;
                return Ok((a, b, c, d));
            })
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_tagged_ok() {
    let tests : &[(i64, &[u8])] = &[
        (10, &[163, 3, 2, 1, 10]),
        (266, &[163, 4, 2, 2, 1, 10]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_i64()
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }

    let tests : &[((i64, bool), &[u8])] = &[
        ((10, false), &[163, 8, 48, 6, 2, 1, 10, 1, 1, 0]),
        ((266, false), &[163, 9, 48, 7, 2, 2, 1, 10, 1, 1, 0]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_sequence(|reader| {
                    let i = reader.next().read_i64()?;
                    let b = reader.next().read_bool()?;
                    return Ok((i, b));
                })
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_der_read_tagged_err() {
    let tests : &[&[u8]] = &[
        &[], &[163], &[0, 0], &[0, 1, 0], &[160, 3, 2, 1, 10],
        &[35, 3, 2, 1, 10], &[131, 3, 2, 1, 10],
        &[131, 1, 10],
        &[163, 128, 2, 1, 10, 0, 0],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_sequence(|reader| {
                    let i = reader.next().read_i64()?;
                    let b = reader.next().read_bool()?;
                    return Ok((i, b));
                })
            })
        }).unwrap_err();
    }

    let tests : &[&[u8]] = &[
        &[], &[163], &[0, 0], &[0, 1, 0],
        &[160, 8, 48, 6, 2, 1, 10, 1, 1, 0],
        &[35, 8, 48, 6, 2, 1, 10, 1, 1, 0],
        &[131, 8, 48, 6, 2, 1, 10, 1, 1, 0],
        &[163, 8, 48, 6, 2, 1, 10, 1, 1, 0, 0],
        &[163, 8, 48, 6, 2, 1, 10, 1, 1],
        &[163, 9, 48, 7, 2, 2, 1, 10, 1, 1, 0, 0],
        &[163, 9, 48, 7, 2, 2, 1, 10, 1, 1],
        &[163, 6, 2, 1, 10, 1, 1, 0],
        &[163, 7, 2, 2, 1, 10, 1, 1, 0],
        &[163, 128, 48, 6, 2, 1, 10, 1, 1, 0, 0, 0, 0],
        &[163, 128, 48, 6, 2, 1, 10, 1, 1, 0, 0, 0],
        &[163, 128, 48, 6, 2, 1, 10, 1, 1, 0, 0],
        &[163, 128, 48, 7, 2, 2, 1, 10, 1, 1, 0, 0, 0, 0],
        &[163, 128, 48, 7, 2, 2, 1, 10, 1, 1, 0, 0, 0],
        &[163, 128, 48, 7, 2, 2, 1, 10, 1, 1, 0, 0],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_i64()
            })
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_tagged_ok() {
    let tests : &[(i64, &[u8])] = &[
        (10, &[163, 3, 2, 1, 10]),
        (266, &[163, 4, 2, 2, 1, 10]),
        (10, &[163, 128, 2, 1, 10, 0, 0]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_i64()
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }

    let tests : &[((i64, bool), &[u8])] = &[
        ((10, false), &[163, 8, 48, 6, 2, 1, 10, 1, 1, 0]),
        ((266, false), &[163, 9, 48, 7, 2, 2, 1, 10, 1, 1, 0]),
        ((10, false), &[163, 128, 48, 6, 2, 1, 10, 1, 1, 0, 0, 0]),
        ((266, false), &[163, 128, 48, 7, 2, 2, 1, 10, 1, 1, 0, 0, 0]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_sequence(|reader| {
                    let i = reader.next().read_i64()?;
                    let b = reader.next().read_bool()?;
                    return Ok((i, b));
                })
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_ber_read_tagged_err() {
    let tests : &[&[u8]] = &[
        &[], &[163], &[0, 0], &[0, 1, 0], &[160, 3, 2, 1, 10],
        &[35, 3, 2, 1, 10], &[131, 3, 2, 1, 10],
        &[131, 1, 10],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_sequence(|reader| {
                    let i = reader.next().read_i64()?;
                    let b = reader.next().read_bool()?;
                    return Ok((i, b));
                })
            })
        }).unwrap_err();
    }

    let tests : &[&[u8]] = &[
        &[], &[163], &[0, 0], &[0, 1, 0],
        &[160, 8, 48, 6, 2, 1, 10, 1, 1, 0],
        &[35, 8, 48, 6, 2, 1, 10, 1, 1, 0],
        &[131, 8, 48, 6, 2, 1, 10, 1, 1, 0],
        &[163, 8, 48, 6, 2, 1, 10, 1, 1, 0, 0],
        &[163, 8, 48, 6, 2, 1, 10, 1, 1],
        &[163, 9, 48, 7, 2, 2, 1, 10, 1, 1, 0, 0],
        &[163, 9, 48, 7, 2, 2, 1, 10, 1, 1],
        &[163, 6, 2, 1, 10, 1, 1, 0],
        &[163, 7, 2, 2, 1, 10, 1, 1, 0],
        &[163, 128, 48, 6, 2, 1, 10, 1, 1, 0, 0, 0, 0],
        &[163, 128, 48, 6, 2, 1, 10, 1, 1, 0, 0],
        &[163, 128, 48, 7, 2, 2, 1, 10, 1, 1, 0, 0, 0, 0],
        &[163, 128, 48, 7, 2, 2, 1, 10, 1, 1, 0, 0],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_i64()
            })
        }).unwrap_err();
    }
}

#[test]
fn test_der_read_tagged_implicit_ok() {
    let tests : &[(i64, &[u8])] = &[
        (10, &[131, 1, 10]),
        (266, &[131, 2, 1, 10]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_tagged_implicit(Tag::context(3), |reader| {
                reader.read_i64()
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }

    let tests : &[((i64, bool), &[u8])] = &[
        ((10, false), &[163, 6, 2, 1, 10, 1, 1, 0]),
        ((266, false), &[163, 7, 2, 2, 1, 10, 1, 1, 0]),
    ];
    for &(evalue, data) in tests {
        let value = parse_der(data, |reader| {
            reader.read_tagged_implicit(Tag::context(3), |reader| {
                reader.read_sequence(|reader| {
                    let i = reader.next().read_i64()?;
                    let b = reader.next().read_bool()?;
                    return Ok((i, b));
                })
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_der_read_tagged_implicit_err() {
    let tests : &[&[u8]] = &[
        &[], &[131], &[0, 0], &[0, 1, 0], &[128, 3, 2, 1, 10],
        &[3, 3, 2, 1, 10], &[163, 3, 2, 1, 10],
        &[163, 3, 2, 1, 10],
        &[131, 128, 1, 10, 0, 0],
        &[163, 128, 2, 1, 10, 0, 0],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_sequence(|reader| {
                    let i = reader.next().read_i64()?;
                    let b = reader.next().read_bool()?;
                    return Ok((i, b));
                })
            })
        }).unwrap_err();
    }

    let tests : &[&[u8]] = &[
        &[], &[163], &[0, 0], &[0, 1, 0],
        &[160, 6, 2, 1, 10, 1, 1, 0],
        &[35, 6, 2, 1, 10, 1, 1, 0],
        &[131, 6, 2, 1, 10, 1, 1, 0],
        &[163, 6, 2, 1, 10, 1, 1, 0, 0],
        &[163, 6, 2, 1, 10, 1, 1],
        &[163, 7, 2, 2, 1, 10, 1, 1, 0, 0],
        &[163, 7, 2, 2, 1, 10, 1, 1],
        &[163, 8, 48, 6, 2, 1, 10, 1, 1, 0],
        &[163, 9, 48, 7, 2, 2, 1, 10, 1, 1, 0],
        &[163, 128, 2, 1, 10, 1, 1, 0, 0, 0, 0],
        &[163, 128, 2, 1, 10, 1, 1, 0, 0, 0],
        &[163, 128, 2, 1, 10, 1, 1, 0, 0],
        &[163, 128, 2, 2, 1, 10, 1, 1, 0, 0, 0, 0],
        &[163, 128, 2, 2, 1, 10, 1, 1, 0, 0, 0],
        &[163, 128, 2, 2, 1, 10, 1, 1, 0, 0],
    ];
    for &data in tests {
        parse_der(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_i64()
            })
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_tagged_implicit_ok() {
    let tests : &[(i64, &[u8])] = &[
        (10, &[131, 1, 10]),
        (266, &[131, 2, 1, 10]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_tagged_implicit(Tag::context(3), |reader| {
                reader.read_i64()
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }

    let tests : &[((i64, bool), &[u8])] = &[
        ((10, false), &[163, 6, 2, 1, 10, 1, 1, 0]),
        ((266, false), &[163, 7, 2, 2, 1, 10, 1, 1, 0]),
        ((10, false), &[163, 128, 2, 1, 10, 1, 1, 0, 0, 0]),
        ((266, false), &[163, 128, 2, 2, 1, 10, 1, 1, 0, 0, 0]),
    ];
    for &(evalue, data) in tests {
        let value = parse_ber(data, |reader| {
            reader.read_tagged_implicit(Tag::context(3), |reader| {
                reader.read_sequence(|reader| {
                    let i = reader.next().read_i64()?;
                    let b = reader.next().read_bool()?;
                    return Ok((i, b));
                })
            })
        }).unwrap();
        assert_eq!(value, evalue);
    }
}

#[test]
fn test_ber_read_tagged_implicit_err() {
    let tests : &[&[u8]] = &[
        &[], &[131], &[0, 0], &[0, 1, 0], &[128, 3, 2, 1, 10],
        &[3, 3, 2, 1, 10], &[163, 3, 2, 1, 10],
        &[163, 3, 2, 1, 10],
        &[131, 128, 1, 10, 0, 0],
        &[163, 128, 2, 1, 10, 0, 0],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_sequence(|reader| {
                    let i = reader.next().read_i64()?;
                    let b = reader.next().read_bool()?;
                    return Ok((i, b));
                })
            })
        }).unwrap_err();
    }

    let tests : &[&[u8]] = &[
        &[], &[163], &[0, 0], &[0, 1, 0],
        &[160, 6, 2, 1, 10, 1, 1, 0],
        &[35, 6, 2, 1, 10, 1, 1, 0],
        &[131, 6, 2, 1, 10, 1, 1, 0],
        &[163, 6, 2, 1, 10, 1, 1, 0, 0],
        &[163, 6, 2, 1, 10, 1, 1],
        &[163, 7, 2, 2, 1, 10, 1, 1, 0, 0],
        &[163, 7, 2, 2, 1, 10, 1, 1],
        &[163, 8, 48, 6, 2, 1, 10, 1, 1, 0],
        &[163, 9, 48, 7, 2, 2, 1, 10, 1, 1, 0],
        &[163, 128, 2, 1, 10, 1, 1, 0, 0, 0, 0],
        &[163, 128, 2, 1, 10, 1, 1, 0, 0],
        &[163, 128, 2, 2, 1, 10, 1, 1, 0, 0, 0, 0],
        &[163, 128, 2, 2, 1, 10, 1, 1, 0, 0],
    ];
    for &data in tests {
        parse_ber(data, |reader| {
            reader.read_tagged(Tag::context(3), |reader| {
                reader.read_i64()
            })
        }).unwrap_err();
    }
}

#[test]
fn test_ber_read_overflow() {
    let data = [33, 136, 255, 255, 255, 255, 255, 255, 255, 255];

    let r: Result<bool, _> = parse_ber(&data, |reader| {
        reader.read_bool()
    });

    let err = r.unwrap_err();

    assert_eq!(err.kind(), ASN1ErrorKind::IntegerOverflow);
}
